//! Memory-only, policy-checked Google Drive resumable uploads.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::ProxyService;
use crate::{ProxyError, ProxyRequest};

pub const MAX_DRIVE_UPLOAD_BYTES: u64 = 250 * 1024 * 1024;
pub const DRIVE_UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_SESSIONS: usize = 16;
const MAX_SESSIONS_PER_AGENT: usize = 4;
const MAX_RECONCILE_ATTEMPTS: u32 = 5;

#[derive(Clone)]
pub(super) struct DriveUploadSessions {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<DriveUploadSession>>>>>,
    starts: Arc<Mutex<()>>,
    chunk_permits: Arc<tokio::sync::Semaphore>,
}

impl Default for DriveUploadSessions {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            starts: Arc::new(Mutex::new(())),
            chunk_permits: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}

struct DriveUploadSession {
    agent_id: String,
    selector: String,
    name: String,
    parent_id: Option<String>,
    idempotency_key: Option<String>,
    file_id: String,
    google_session_uri: Zeroizing<String>,
    mime_type: String,
    size_bytes: u64,
    acknowledged: u64,
    updated_at: Instant,
    completed: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveUploadStart {
    pub name: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub parent_id: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DriveUploadSessionInfo {
    pub agent: String,
    pub connection: String,
    pub upload_id: String,
    pub file_id: String,
    pub chunk_size: usize,
    pub size_bytes: u64,
    pub acknowledged_bytes: u64,
    pub expires_in_seconds: u64,
    pub completed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DriveUploadChunkResult {
    Incomplete { acknowledged_bytes: u64 },
    Complete { file: serde_json::Value },
}

#[derive(Debug, Serialize)]
pub struct DriveUploadStatus {
    pub upload_id: String,
    pub file_id: String,
    pub size_bytes: u64,
    pub acknowledged_bytes: u64,
    pub completed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
}

#[derive(thiserror::Error, Debug)]
pub enum DriveUploadError {
    #[error("{0}")]
    Invalid(String),
    #[error("upload exceeds the 250 MiB limit")]
    TooLarge,
    #[error("upload session not found")]
    NotFound,
    #[error("upload session expired")]
    Expired,
    #[error("upload session conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
}

impl DriveUploadError {
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Expired => StatusCode::GONE,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Proxy(err) => err.status_code(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "drive.upload.invalid_request",
            Self::TooLarge => "drive.upload.too_large",
            Self::NotFound => "drive.upload.not_found",
            Self::Expired => "drive.upload.expired",
            Self::Conflict(_) => "drive.upload.conflict",
            Self::Proxy(err) => err.error_code(),
        }
    }
}

impl ProxyService {
    pub async fn drive_upload_start(
        &self,
        agent_id: String,
        selector: String,
        request_id: String,
        start: DriveUploadStart,
    ) -> Result<DriveUploadSessionInfo, DriveUploadError> {
        validate_start(&start)?;
        // Serializing starts makes the idempotency lookup and insertion atomic
        // across the two upstream requests needed to create a resumable upload.
        let _start_guard = self.drive_uploads.starts.lock().await;
        self.drive_uploads.prune().await;
        if let Some(existing) =
            self.drive_uploads.find_idempotent(&agent_id, &selector, &start).await?
        {
            return Ok(existing);
        }
        self.drive_uploads.check_capacity(&agent_id).await?;

        // Resolve the connection before constructing the upload endpoint so
        // integration tests and future connector definitions can supply their
        // own allowed Google-compatible origin. Production's built-in Drive
        // connector resolves to https://www.googleapis.com/drive/v3/.
        let (_, resolved_connector_id) =
            self.resolve_connection(&agent_id, &selector, "drive.file").await?;
        let (mut initiation_url, _, _) =
            self.resolve_upstream(&selector, resolved_connector_id.as_deref())?;
        initiation_url.set_path("/upload/drive/v3/files");
        initiation_url.set_query(Some(&format!(
            "uploadType=resumable&supportsAllDrives=true&fields={}",
            urlencoding::encode("id,name,mimeType,size,md5Checksum,parents,webViewLink")
        )));

        let file_id_response = self
            .drive_upload_proxy_call(
                &agent_id,
                &selector,
                &request_id,
                "uploads/generate-id",
                "files/generateIds?count=1&space=drive&type=files".to_owned(),
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
            )
            .await?;
        ensure_success(file_id_response.status, &file_id_response.body, "generate Drive file ID")?;
        let generated: serde_json::Value = serde_json::from_slice(&file_id_response.body)
            .map_err(|e| DriveUploadError::Invalid(format!("invalid generateIds response: {e}")))?;
        let file_id = generated["ids"]
            .as_array()
            .and_then(|ids| ids.first())
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                DriveUploadError::Invalid("Google returned no generated file ID".to_owned())
            })?
            .to_owned();

        let mut metadata = serde_json::json!({ "id": file_id, "name": start.name.clone() });
        if let Some(parent) = &start.parent_id {
            metadata["parents"] = serde_json::json!([parent]);
        }
        let body = serde_json::to_vec(&metadata)
            .map(Bytes::from)
            .map_err(|e| DriveUploadError::Invalid(format!("invalid upload metadata: {e}")))?;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json; charset=UTF-8"));
        headers.insert(
            "x-upload-content-type",
            HeaderValue::from_str(&start.mime_type)
                .map_err(|_| DriveUploadError::Invalid("invalid MIME type".to_owned()))?,
        );
        headers.insert(
            "x-upload-content-length",
            HeaderValue::from_str(&start.size_bytes.to_string())
                .map_err(|_| DriveUploadError::Invalid("invalid file size".to_owned()))?,
        );
        let path = initiation_url.to_string();
        let response = self
            .drive_upload_proxy_call(
                &agent_id,
                &selector,
                &request_id,
                "uploads/initiate",
                path,
                Method::POST,
                headers,
                body,
            )
            .await?;
        ensure_success(response.status, &response.body, "initiate Drive upload")?;
        let location =
            response.headers.get("location").and_then(|value| value.to_str().ok()).ok_or_else(
                || DriveUploadError::Invalid("Google returned no resumable session URI".to_owned()),
            )?;
        validate_google_session_uri(location, &initiation_url)?;

        let upload_id = random_upload_id();
        let completed = if start.size_bytes == 0 {
            Some(
                self.finish_zero_byte_upload(
                    &agent_id,
                    &selector,
                    &request_id,
                    location,
                    &start.mime_type,
                )
                .await?,
            )
        } else {
            None
        };
        let session = DriveUploadSession {
            agent_id: agent_id.clone(),
            selector: selector.clone(),
            name: start.name,
            parent_id: start.parent_id,
            idempotency_key: start.idempotency_key,
            file_id: file_id.clone(),
            google_session_uri: Zeroizing::new(location.to_owned()),
            mime_type: start.mime_type,
            size_bytes: start.size_bytes,
            acknowledged: 0,
            updated_at: Instant::now(),
            completed: completed.clone(),
        };
        self.drive_uploads
            .inner
            .lock()
            .await
            .insert(upload_id.clone(), Arc::new(Mutex::new(session)));

        Ok(DriveUploadSessionInfo {
            agent: agent_id,
            connection: selector,
            upload_id,
            file_id,
            chunk_size: DRIVE_UPLOAD_CHUNK_BYTES,
            size_bytes: start.size_bytes,
            acknowledged_bytes: if completed.is_some() { start.size_bytes } else { 0 },
            expires_in_seconds: SESSION_TTL.as_secs(),
            completed: completed.is_some(),
            file: completed,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn drive_upload_chunk(
        &self,
        agent_id: String,
        selector: String,
        request_id: String,
        upload_id: &str,
        content_range: &str,
        body: Bytes,
    ) -> Result<DriveUploadChunkResult, DriveUploadError> {
        let _permit =
            self.drive_uploads.chunk_permits.clone().acquire_owned().await.map_err(|_| {
                DriveUploadError::Conflict("upload service is shutting down".to_owned())
            })?;
        if body.len() > DRIVE_UPLOAD_CHUNK_BYTES {
            return Err(DriveUploadError::TooLarge);
        }
        let session = self.drive_uploads.get(upload_id).await?;
        let mut session = session.lock().await;
        session.ensure_owner(&agent_id, &selector)?;
        session.ensure_live()?;
        if let Some(file) = &session.completed {
            return Ok(DriveUploadChunkResult::Complete { file: file.clone() });
        }
        let (start, end, total) = parse_content_range(content_range)?;
        if total != session.size_bytes || start != session.acknowledged {
            return Err(DriveUploadError::Conflict(format!(
                "expected range beginning at {} with total {}, received {content_range}",
                session.acknowledged, session.size_bytes
            )));
        }
        let expected_len = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| DriveUploadError::Invalid("invalid Content-Range".to_owned()))?;
        if expected_len != body.len() as u64 || end >= total {
            return Err(DriveUploadError::Invalid(
                "Content-Range does not match chunk body or declared total".to_owned(),
            ));
        }
        if end + 1 < total && body.len() != DRIVE_UPLOAD_CHUNK_BYTES {
            return Err(DriveUploadError::Invalid(format!(
                "non-final chunks must be exactly {DRIVE_UPLOAD_CHUNK_BYTES} bytes"
            )));
        }

        let original_start = start;
        let mut send_start = start;
        let mut reconcile_attempts = 0;
        loop {
            let offset = usize::try_from(send_start - original_start).map_err(|_| {
                DriveUploadError::Invalid("upload chunk offset overflowed".to_owned())
            })?;
            let response = self
                .put_drive_upload_bytes(
                    &agent_id,
                    &selector,
                    &request_id,
                    upload_id,
                    &session,
                    send_start,
                    end,
                    total,
                    body.slice(offset..),
                )
                .await;
            match response {
                Ok(response) => {
                    session.updated_at = Instant::now();
                    if response.status.as_u16() == 308 {
                        let acknowledged = acknowledged_from_headers(&response.headers)?;
                        validate_acknowledged(acknowledged, send_start, end, total, true)?;
                        session.acknowledged = acknowledged;
                        return Ok(DriveUploadChunkResult::Incomplete {
                            acknowledged_bytes: acknowledged,
                        });
                    }
                    return complete_upload_response(&mut session, total, response);
                }
                Err(DriveUploadError::Proxy(error)) if is_transient_upload_error(&error) => {
                    let mut last_error = error;
                    loop {
                        if reconcile_attempts >= MAX_RECONCILE_ATTEMPTS {
                            return Err(DriveUploadError::Proxy(last_error));
                        }
                        tokio::time::sleep(reconcile_delay(reconcile_attempts)).await;
                        reconcile_attempts += 1;
                        match self
                            .probe_drive_upload(
                                &agent_id,
                                &selector,
                                &request_id,
                                upload_id,
                                &session,
                            )
                            .await
                        {
                            Ok(response) if response.status.as_u16() == 308 => {
                                let acknowledged = acknowledged_from_headers(&response.headers)?;
                                validate_acknowledged(
                                    acknowledged,
                                    session.acknowledged,
                                    end,
                                    total,
                                    false,
                                )?;
                                session.acknowledged = acknowledged;
                                session.updated_at = Instant::now();
                                if acknowledged > end {
                                    return Ok(DriveUploadChunkResult::Incomplete {
                                        acknowledged_bytes: acknowledged,
                                    });
                                }
                                send_start = acknowledged;
                                break;
                            }
                            Ok(response) => {
                                session.updated_at = Instant::now();
                                return complete_upload_response(&mut session, total, response);
                            }
                            Err(DriveUploadError::Proxy(error))
                                if is_transient_upload_error(&error) =>
                            {
                                last_error = error;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn drive_upload_status(
        &self,
        agent_id: &str,
        selector: &str,
        upload_id: &str,
    ) -> Result<DriveUploadStatus, DriveUploadError> {
        let session = self.drive_uploads.get(upload_id).await?;
        let mut session = session.lock().await;
        session.ensure_owner(agent_id, selector)?;
        session.ensure_live()?;
        session.updated_at = Instant::now();
        Ok(DriveUploadStatus {
            upload_id: upload_id.to_owned(),
            file_id: session.file_id.clone(),
            size_bytes: session.size_bytes,
            acknowledged_bytes: session.acknowledged,
            completed: session.completed.is_some(),
            file: session.completed.clone(),
        })
    }

    pub async fn drive_upload_cancel(
        &self,
        agent_id: &str,
        selector: &str,
        upload_id: &str,
    ) -> Result<(), DriveUploadError> {
        let session = self.drive_uploads.get(upload_id).await?;
        {
            let session = session.lock().await;
            session.ensure_owner(agent_id, selector)?;
        }
        self.drive_uploads.inner.lock().await.remove(upload_id);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_upload_proxy_call(
        &self,
        agent_id: &str,
        selector: &str,
        request_id: &str,
        resource: &str,
        path: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<crate::ProxyResponse, DriveUploadError> {
        self.fetch_raw(ProxyRequest {
            service: selector.to_owned(),
            scope: "drive.file".to_owned(),
            resource: resource.to_owned(),
            method,
            path,
            headers,
            body,
            agent_id: agent_id.to_owned(),
            request_id: request_id.to_owned(),
        })
        .await
        .map_err(DriveUploadError::Proxy)
    }

    async fn finish_zero_byte_upload(
        &self,
        agent_id: &str,
        selector: &str,
        request_id: &str,
        uri: &str,
        mime_type: &str,
    ) -> Result<serde_json::Value, DriveUploadError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_str(mime_type)
                .map_err(|_| DriveUploadError::Invalid("invalid MIME type".to_owned()))?,
        );
        headers.insert("content-range", HeaderValue::from_static("bytes */0"));
        let mut attempts = 0;
        loop {
            match self
                .drive_upload_proxy_call(
                    agent_id,
                    selector,
                    request_id,
                    "uploads/zero-byte",
                    uri.to_owned(),
                    Method::PUT,
                    headers.clone(),
                    Bytes::new(),
                )
                .await
            {
                Ok(response) => {
                    ensure_success(
                        response.status,
                        &response.body,
                        "complete zero-byte Drive upload",
                    )?;
                    return serde_json::from_slice(&response.body).map_err(|e| {
                        DriveUploadError::Invalid(format!("invalid Drive completion response: {e}"))
                    });
                }
                Err(DriveUploadError::Proxy(error))
                    if is_transient_upload_error(&error) && attempts < MAX_RECONCILE_ATTEMPTS =>
                {
                    tokio::time::sleep(reconcile_delay(attempts)).await;
                    attempts += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_drive_upload_bytes(
        &self,
        agent_id: &str,
        selector: &str,
        request_id: &str,
        upload_id: &str,
        session: &DriveUploadSession,
        start: u64,
        end: u64,
        total: u64,
        body: Bytes,
    ) -> Result<crate::ProxyResponse, DriveUploadError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_str(&session.mime_type)
                .map_err(|_| DriveUploadError::Invalid("invalid stored MIME type".to_owned()))?,
        );
        headers.insert(
            "content-range",
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}"))
                .map_err(|_| DriveUploadError::Invalid("invalid Content-Range".to_owned()))?,
        );
        self.drive_upload_proxy_call(
            agent_id,
            selector,
            request_id,
            &format!("uploads/{upload_id}"),
            session.google_session_uri.to_string(),
            Method::PUT,
            headers,
            body,
        )
        .await
    }

    async fn probe_drive_upload(
        &self,
        agent_id: &str,
        selector: &str,
        request_id: &str,
        upload_id: &str,
        session: &DriveUploadSession,
    ) -> Result<crate::ProxyResponse, DriveUploadError> {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("0"));
        headers.insert(
            "content-range",
            HeaderValue::from_str(&format!("bytes */{}", session.size_bytes))
                .map_err(|_| DriveUploadError::Invalid("invalid stored upload size".to_owned()))?,
        );
        self.drive_upload_proxy_call(
            agent_id,
            selector,
            request_id,
            &format!("uploads/{upload_id}/status"),
            session.google_session_uri.to_string(),
            Method::PUT,
            headers,
            Bytes::new(),
        )
        .await
    }
}

impl DriveUploadSessions {
    async fn find_idempotent(
        &self,
        agent_id: &str,
        selector: &str,
        start: &DriveUploadStart,
    ) -> Result<Option<DriveUploadSessionInfo>, DriveUploadError> {
        let Some(key) = start.idempotency_key.as_deref() else {
            return Ok(None);
        };
        let entries: Vec<(String, Arc<Mutex<DriveUploadSession>>)> = self
            .inner
            .lock()
            .await
            .iter()
            .map(|(id, session)| (id.clone(), Arc::clone(session)))
            .collect();
        for (upload_id, session) in entries {
            let mut session = session.lock().await;
            if session.agent_id != agent_id
                || session.selector != selector
                || session.idempotency_key.as_deref() != Some(key)
            {
                continue;
            }
            if session.name != start.name
                || session.mime_type != start.mime_type
                || session.size_bytes != start.size_bytes
                || session.parent_id != start.parent_id
            {
                return Err(DriveUploadError::Conflict(
                    "idempotency key was already used for different upload metadata".to_owned(),
                ));
            }
            session.ensure_live()?;
            session.updated_at = Instant::now();
            return Ok(Some(DriveUploadSessionInfo {
                agent: agent_id.to_owned(),
                connection: selector.to_owned(),
                upload_id,
                file_id: session.file_id.clone(),
                chunk_size: DRIVE_UPLOAD_CHUNK_BYTES,
                size_bytes: session.size_bytes,
                acknowledged_bytes: session.acknowledged,
                expires_in_seconds: SESSION_TTL.as_secs(),
                completed: session.completed.is_some(),
                file: session.completed.clone(),
            }));
        }
        Ok(None)
    }

    async fn prune(&self) {
        let entries: Vec<(String, Arc<Mutex<DriveUploadSession>>)> = self
            .inner
            .lock()
            .await
            .iter()
            .map(|(id, session)| (id.clone(), Arc::clone(session)))
            .collect();
        let mut expired = Vec::new();
        for (id, session) in entries {
            if session.lock().await.updated_at.elapsed() > SESSION_TTL {
                expired.push(id);
            }
        }
        let mut sessions = self.inner.lock().await;
        for id in expired {
            sessions.remove(&id);
        }
    }

    async fn check_capacity(&self, agent_id: &str) -> Result<(), DriveUploadError> {
        let entries: Vec<(String, Arc<Mutex<DriveUploadSession>>)> = self
            .inner
            .lock()
            .await
            .iter()
            .map(|(id, session)| (id.clone(), Arc::clone(session)))
            .collect();
        let mut per_agent = 0;
        let mut active = 0;
        let mut completed = Vec::new();
        for (id, session) in &entries {
            let session = session.lock().await;
            if session.completed.is_some() {
                completed.push((id.clone(), session.updated_at));
                continue;
            }
            active += 1;
            if session.agent_id == agent_id {
                per_agent += 1;
            }
        }
        if active >= MAX_SESSIONS {
            return Err(DriveUploadError::Conflict("too many active upload sessions".to_owned()));
        }
        if per_agent >= MAX_SESSIONS_PER_AGENT {
            return Err(DriveUploadError::Conflict(
                "agent already has the maximum number of active upload sessions".to_owned(),
            ));
        }

        // Completed sessions are retained for idempotent result recovery, but
        // must not make a busy agent wait 30 minutes before its next upload.
        // Keep the newest results and evict only as many old completed entries
        // as needed to preserve the hard in-memory session bound.
        let evict_count = entries.len().saturating_add(1).saturating_sub(MAX_SESSIONS);
        if evict_count > 0 {
            completed.sort_by_key(|(_, updated_at)| *updated_at);
            let mut sessions = self.inner.lock().await;
            for (id, _) in completed.into_iter().take(evict_count) {
                sessions.remove(&id);
            }
        }
        Ok(())
    }

    async fn get(
        &self,
        upload_id: &str,
    ) -> Result<Arc<Mutex<DriveUploadSession>>, DriveUploadError> {
        self.inner.lock().await.get(upload_id).cloned().ok_or(DriveUploadError::NotFound)
    }
}

impl DriveUploadSession {
    fn ensure_owner(&self, agent_id: &str, selector: &str) -> Result<(), DriveUploadError> {
        if self.agent_id != agent_id || self.selector != selector {
            return Err(DriveUploadError::NotFound);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), DriveUploadError> {
        if self.updated_at.elapsed() > SESSION_TTL {
            return Err(DriveUploadError::Expired);
        }
        Ok(())
    }
}

fn validate_start(start: &DriveUploadStart) -> Result<(), DriveUploadError> {
    let name = start.name.trim();
    if name.is_empty() || start.name.chars().any(char::is_control) {
        return Err(DriveUploadError::Invalid(
            "file name must be non-empty and contain no control characters".to_owned(),
        ));
    }
    let parsed: mime::Mime = start
        .mime_type
        .parse()
        .map_err(|_| DriveUploadError::Invalid("invalid MIME type".to_owned()))?;
    if parsed.essence_str().starts_with("application/vnd.google-apps.") {
        return Err(DriveUploadError::Invalid(
            "Google Workspace conversion MIME types are not supported for binary upload".to_owned(),
        ));
    }
    if start.size_bytes > MAX_DRIVE_UPLOAD_BYTES {
        return Err(DriveUploadError::TooLarge);
    }
    if let Some(parent) = &start.parent_id
        && (parent.is_empty()
            || parent.len() > 256
            || !parent.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return Err(DriveUploadError::Invalid("invalid Drive parent ID".to_owned()));
    }
    if let Some(key) = &start.idempotency_key
        && (key.is_empty() || key.len() > 128 || key.chars().any(char::is_control))
    {
        return Err(DriveUploadError::Invalid("invalid idempotency key".to_owned()));
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Result<(u64, u64, u64), DriveUploadError> {
    let rest = value.strip_prefix("bytes ").ok_or_else(|| {
        DriveUploadError::Invalid("Content-Range must start with 'bytes '".to_owned())
    })?;
    let (range, total) = rest
        .split_once('/')
        .ok_or_else(|| DriveUploadError::Invalid("invalid Content-Range".to_owned()))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| DriveUploadError::Invalid("invalid Content-Range".to_owned()))?;
    let start =
        start.parse().map_err(|_| DriveUploadError::Invalid("invalid range start".to_owned()))?;
    let end = end.parse().map_err(|_| DriveUploadError::Invalid("invalid range end".to_owned()))?;
    let total =
        total.parse().map_err(|_| DriveUploadError::Invalid("invalid range total".to_owned()))?;
    if start > end || total == 0 {
        return Err(DriveUploadError::Invalid("invalid Content-Range bounds".to_owned()));
    }
    Ok((start, end, total))
}

fn acknowledged_from_headers(headers: &HeaderMap) -> Result<u64, DriveUploadError> {
    let Some(value) = headers.get("range") else {
        return Ok(0);
    };
    let text = value.to_str().map_err(|_| {
        DriveUploadError::Invalid("Google returned an invalid Range header".to_owned())
    })?;
    let end = text
        .strip_prefix("bytes=0-")
        .ok_or_else(|| {
            DriveUploadError::Invalid("Google returned an unexpected Range header".to_owned())
        })?
        .parse::<u64>()
        .map_err(|_| {
            DriveUploadError::Invalid("Google returned an invalid Range offset".to_owned())
        })?;
    end.checked_add(1).ok_or_else(|| {
        DriveUploadError::Invalid("Google returned an overflowing Range offset".to_owned())
    })
}

fn validate_acknowledged(
    acknowledged: u64,
    lower_bound: u64,
    chunk_end: u64,
    total: u64,
    must_advance: bool,
) -> Result<(), DriveUploadError> {
    let valid_lower =
        if must_advance { acknowledged > lower_bound } else { acknowledged >= lower_bound };
    if !valid_lower || acknowledged > chunk_end + 1 || acknowledged > total {
        return Err(DriveUploadError::Conflict(
            "Google acknowledged an invalid upload offset".to_owned(),
        ));
    }
    if acknowledged == total {
        return Err(DriveUploadError::Conflict(
            "Google acknowledged all bytes without returning final file metadata".to_owned(),
        ));
    }
    Ok(())
}

fn complete_upload_response(
    session: &mut DriveUploadSession,
    total: u64,
    response: crate::ProxyResponse,
) -> Result<DriveUploadChunkResult, DriveUploadError> {
    ensure_success(response.status, &response.body, "upload Drive chunk")?;
    let file: serde_json::Value = serde_json::from_slice(&response.body).map_err(|e| {
        DriveUploadError::Invalid(format!("invalid Drive completion response: {e}"))
    })?;
    session.acknowledged = total;
    session.completed = Some(file.clone());
    Ok(DriveUploadChunkResult::Complete { file })
}

fn is_transient_upload_error(error: &ProxyError) -> bool {
    matches!(
        error,
        ProxyError::UpstreamUnreachable { .. }
            | ProxyError::UpstreamRateLimited { .. }
            | ProxyError::UpstreamServerError { .. }
    ) || matches!(
        error,
        ProxyError::Internal { message }
            if message.starts_with("failed to read upstream response body:")
                || message.starts_with("upstream request failed:")
    )
}

fn reconcile_delay(attempt: u32) -> Duration {
    Duration::from_millis(250_u64.saturating_mul(1_u64 << attempt.min(4)))
}

fn validate_google_session_uri(
    uri: &str,
    initiation_url: &url::Url,
) -> Result<(), DriveUploadError> {
    let parsed = url::Url::parse(uri).map_err(|_| {
        DriveUploadError::Invalid("Google returned an invalid session URI".to_owned())
    })?;
    if parsed.scheme() != initiation_url.scheme()
        || parsed.host_str() != initiation_url.host_str()
        || parsed.port_or_known_default() != initiation_url.port_or_known_default()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/upload/drive/v3/files"
    {
        return Err(DriveUploadError::Invalid(
            "Google returned an untrusted session URI".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_success(
    status: StatusCode,
    body: &[u8],
    operation: &str,
) -> Result<(), DriveUploadError> {
    if status.is_success() {
        return Ok(());
    }
    let detail = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/message").and_then(serde_json::Value::as_str).map(str::to_owned)
        })
        .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
    Err(DriveUploadError::Invalid(format!("failed to {operation}: {detail}")))
}

fn random_upload_id() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_ranges() {
        assert!(matches!(parse_content_range("bytes 0-7/10"), Ok((0, 7, 10))));
        assert!(parse_content_range("bytes 8-7/10").is_err());
        assert!(parse_content_range("items 0-7/10").is_err());
    }

    #[test]
    fn validates_google_upload_uris() {
        let validation = url::Url::parse(
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
        )
        .map(|initiation| {
            assert!(
                validate_google_session_uri(
                    "https://www.googleapis.com/upload/drive/v3/files?upload_id=secret",
                    &initiation,
                )
                .is_ok()
            );
            assert!(
                validate_google_session_uri(
                    "https://evil.example/upload/drive/v3/files?upload_id=secret",
                    &initiation,
                )
                .is_err()
            );
            assert!(
                validate_google_session_uri(
                    "http://www.googleapis.com/upload/drive/v3/files?upload_id=secret",
                    &initiation,
                )
                .is_err()
            );
        });
        assert!(validation.is_ok());
    }

    #[test]
    fn validates_limits_and_native_mime() {
        let mut request = DriveUploadStart {
            name: "report.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            size_bytes: MAX_DRIVE_UPLOAD_BYTES,
            parent_id: None,
            idempotency_key: None,
        };
        assert!(validate_start(&request).is_ok());
        request.size_bytes += 1;
        assert!(matches!(validate_start(&request), Err(DriveUploadError::TooLarge)));
        request.size_bytes = 1;
        request.mime_type = "application/vnd.google-apps.document".to_owned();
        assert!(validate_start(&request).is_err());
    }

    #[test]
    fn validates_acknowledgement_progress() {
        assert!(validate_acknowledged(8, 0, 7, 10, true).is_ok());
        assert!(validate_acknowledged(0, 0, 7, 10, true).is_err());
        assert!(validate_acknowledged(0, 0, 7, 10, false).is_ok());
        assert!(validate_acknowledged(9, 0, 7, 10, false).is_err());
        assert!(validate_acknowledged(10, 8, 9, 10, false).is_err());
    }

    #[test]
    fn response_read_failures_are_reconciled_as_ambiguous() {
        assert!(is_transient_upload_error(&ProxyError::Internal {
            message: "failed to read upstream response body: connection reset".to_owned(),
        }));
        assert!(!is_transient_upload_error(&ProxyError::Internal {
            message: "unrelated invariant failed".to_owned(),
        }));
    }

    #[tokio::test]
    async fn idempotent_start_reuses_only_identical_metadata() {
        let sessions = DriveUploadSessions::default();
        sessions.inner.lock().await.insert(
            "upload-id".to_owned(),
            Arc::new(Mutex::new(DriveUploadSession {
                agent_id: "agent".to_owned(),
                selector: "drive".to_owned(),
                name: "report.pdf".to_owned(),
                parent_id: Some("folder".to_owned()),
                idempotency_key: Some("key".to_owned()),
                file_id: "file-id".to_owned(),
                google_session_uri: Zeroizing::new(
                    "https://www.googleapis.com/upload/drive/v3/files?upload_id=secret".to_owned(),
                ),
                mime_type: "application/pdf".to_owned(),
                size_bytes: 10,
                acknowledged: 8,
                updated_at: Instant::now(),
                completed: None,
            })),
        );
        let mut start = DriveUploadStart {
            name: "report.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            size_bytes: 10,
            parent_id: Some("folder".to_owned()),
            idempotency_key: Some("key".to_owned()),
        };
        let existing = sessions.find_idempotent("agent", "drive", &start).await;
        assert!(matches!(
            existing,
            Ok(Some(DriveUploadSessionInfo {
                ref upload_id,
                acknowledged_bytes: 8,
                ..
            })) if upload_id == "upload-id"
        ));

        start.name = "different.pdf".to_owned();
        assert!(matches!(
            sessions.find_idempotent("agent", "drive", &start).await,
            Err(DriveUploadError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn completed_sessions_do_not_consume_active_per_agent_capacity() {
        let sessions = DriveUploadSessions::default();
        for index in 0..MAX_SESSIONS_PER_AGENT {
            sessions.inner.lock().await.insert(
                format!("complete-{index}"),
                Arc::new(Mutex::new(DriveUploadSession {
                    agent_id: "agent".to_owned(),
                    selector: "drive".to_owned(),
                    name: format!("{index}.pdf"),
                    parent_id: None,
                    idempotency_key: Some(format!("key-{index}")),
                    file_id: format!("file-{index}"),
                    google_session_uri: Zeroizing::new(format!(
                        "https://www.googleapis.com/upload/drive/v3/files?upload_id={index}"
                    )),
                    mime_type: "application/pdf".to_owned(),
                    size_bytes: 1,
                    acknowledged: 1,
                    updated_at: Instant::now(),
                    completed: Some(serde_json::json!({"id": format!("file-{index}")})),
                })),
            );
        }
        assert!(sessions.check_capacity("agent").await.is_ok());
    }
}
