//! Memory-only Drive download/export sessions.
//!
//! A caller receives only an opaque PermitLayer session id. Google URLs and
//! OAuth credentials remain inside the daemon. Each chunk is a separate
//! `ProxyService::fetch_raw` call so binding, scope and credential state are
//! resolved again at every 8 MiB boundary.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};

use crate::{ProxyRequest, ProxyService};

pub const DRIVE_TRANSFER_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const DRIVE_TRANSFER_MAX_BYTES: u64 = 250 * 1024 * 1024;
const EXPORT_MAX_BYTES: usize = 10 * 1024 * 1024;
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const LRO_POLL_LIMIT: Duration = Duration::from_secs(6 * 60);
const MAX_SIGNED_REDIRECTS: usize = 5;
const MAX_TRANSFER_SESSIONS: usize = 128;
const GOOGLE_VIDS_MIME: &str = "application/vnd.google-apps.vid";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum DriveTransferStart {
    Blob { file_id: String },
    Export { file_id: String, mime_type: String },
    Revision { file_id: String, revision_id: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct DriveTransferSessionInfo {
    pub transfer_id: String,
    pub file_id: String,
    pub name: String,
    pub mime_type: String,
    pub size_bytes: Option<u64>,
    pub md5_checksum: Option<String>,
    pub source_fingerprint: String,
    pub chunk_size: usize,
    pub resumable: bool,
}

#[derive(Debug)]
pub struct DriveTransferChunk {
    pub bytes: Bytes,
    pub offset: u64,
    pub total_size: Option<u64>,
    pub complete: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DriveTransferError {
    #[error("invalid Drive transfer request: {0}")]
    Invalid(String),
    #[error("Drive transfer not found or not owned by this agent")]
    NotFound,
    #[error("Drive transfer expired")]
    Expired,
    #[error("Drive file exceeds the 250 MiB transfer limit")]
    TooLarge,
    #[error("Drive denied this download: {0}")]
    Denied(String),
    #[error("Drive download failed: {0}")]
    Download(String),
    #[error("Drive transfer failed: {0}")]
    Proxy(#[from] crate::ProxyError),
    #[error("Drive transfer service is at capacity; retry later")]
    Busy,
}

impl DriveTransferError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Expired => StatusCode::GONE,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Proxy(_) | Self::Download(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "drive.transfer.invalid",
            Self::NotFound => "drive.transfer.not_found",
            Self::Expired => "drive.transfer.expired",
            Self::TooLarge => "drive.transfer.too_large",
            Self::Denied(_) => "drive.transfer.denied",
            Self::Busy => "drive.transfer.busy",
            Self::Proxy(_) | Self::Download(_) => "drive.transfer.upstream",
        }
    }
}

enum TransferKind {
    Blob,
    Export {
        mime_type: String,
    },
    Revision {
        revision_id: String,
    },
    Vids {
        download_uri: url::Url,
        response: Option<Box<reqwest::Response>>,
        buffered: Vec<u8>,
        eof: bool,
    },
}

struct Session {
    agent: String,
    selector: String,
    file_id: String,
    size: Option<u64>,
    source_etag: Option<HeaderValue>,
    kind: TransferKind,
    cursor: u64,
    touched: Instant,
}

#[derive(Clone)]
pub(super) struct DriveTransferSessions {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<Session>>>>>,
    materialization: Arc<Semaphore>,
}

impl Default for DriveTransferSessions {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            materialization: Arc::new(Semaphore::new(1)),
        }
    }
}

impl DriveTransferSessions {
    async fn prune_expired(&self) {
        let entries: Vec<_> = self
            .inner
            .lock()
            .await
            .iter()
            .map(|(id, session)| (id.clone(), Arc::clone(session)))
            .collect();
        let mut expired = Vec::new();
        for (id, session) in entries {
            if let Ok(session) = session.try_lock()
                && session.touched.elapsed() > SESSION_TTL
            {
                expired.push(id);
            }
        }
        if !expired.is_empty() {
            let mut sessions = self.inner.lock().await;
            for id in expired {
                sessions.remove(&id);
            }
        }
    }

    pub async fn start(
        &self,
        service: &ProxyService,
        agent: String,
        selector: String,
        request_id: String,
        start: DriveTransferStart,
    ) -> Result<DriveTransferSessionInfo, DriveTransferError> {
        self.prune_expired().await;
        if self.inner.lock().await.len() >= MAX_TRANSFER_SESSIONS {
            return Err(DriveTransferError::Busy);
        }
        let (file_id, kind) = match start {
            DriveTransferStart::Blob { file_id } => (file_id, TransferKind::Blob),
            DriveTransferStart::Export { file_id, mime_type } => {
                mime_type.parse::<mime::Mime>().map_err(|_| {
                    DriveTransferError::Invalid("invalid export MIME type".to_owned())
                })?;
                (file_id, TransferKind::Export { mime_type })
            }
            DriveTransferStart::Revision { file_id, revision_id } => {
                validate_id(&revision_id)?;
                (file_id, TransferKind::Revision { revision_id })
            }
        };
        validate_id(&file_id)?;
        let encoded = urlencoding::encode(&file_id);
        let metadata_path = format!(
            "files/{encoded}?supportsAllDrives=true&fields=id,name,mimeType,size,md5Checksum,version,resourceKey,capabilities(canDownload)"
        );
        let metadata = service
            .handle(ProxyRequest {
                service: selector.clone(),
                scope: "drive.readonly".to_owned(),
                resource: metadata_path.clone(),
                method: Method::GET,
                path: metadata_path,
                headers: HeaderMap::new(),
                body: Bytes::new(),
                agent_id: agent.clone(),
                request_id,
            })
            .await?;
        if !metadata.status.is_success() {
            return Err(DriveTransferError::Denied(format!(
                "metadata request returned HTTP {}",
                metadata.status
            )));
        }
        let file_etag = metadata.headers.get(axum::http::header::ETAG).cloned();
        let value: serde_json::Value = serde_json::from_slice(&metadata.body)
            .map_err(|error| DriveTransferError::Invalid(format!("invalid metadata: {error}")))?;
        if value.pointer("/capabilities/canDownload").and_then(serde_json::Value::as_bool)
            == Some(false)
        {
            return Err(DriveTransferError::Denied("capabilities.canDownload is false".to_owned()));
        }
        let file_size: Option<u64> = value
            .get("size")
            .and_then(serde_json::Value::as_str)
            .and_then(|size| size.parse().ok());
        let name =
            value.get("name").and_then(serde_json::Value::as_str).unwrap_or("download").to_owned();
        let source_mime = value
            .get("mimeType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("application/octet-stream");
        let file_md5 =
            value.get("md5Checksum").and_then(serde_json::Value::as_str).map(str::to_owned);
        let file_version =
            value.get("version").and_then(serde_json::Value::as_str).unwrap_or("unknown");
        let mut size = file_size;
        let mut md5 = file_md5.clone();
        let mut source_etag = file_etag;
        let mut mime_type = match &kind {
            TransferKind::Export { mime_type } => mime_type.clone(),
            _ => source_mime.to_owned(),
        };
        let mut fingerprint_parts = vec!["file", &file_id, file_version, source_mime];
        let mut owned_revision_fingerprint = None;

        if let TransferKind::Revision { revision_id } = &kind {
            let revision_path = format!(
                "files/{}/revisions/{}?supportsAllDrives=true&fields=id,mimeType,size,md5Checksum,modifiedTime,keepForever",
                urlencoding::encode(&file_id),
                urlencoding::encode(revision_id)
            );
            let revision = service
                .handle(ProxyRequest {
                    service: selector.clone(),
                    scope: "drive.readonly".to_owned(),
                    resource: revision_path.clone(),
                    method: Method::GET,
                    path: revision_path,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                    agent_id: agent.clone(),
                    request_id: ulid::Ulid::new().to_string(),
                })
                .await?;
            if !revision.status.is_success() {
                return Err(DriveTransferError::Denied(format!(
                    "revision metadata request returned HTTP {}",
                    revision.status
                )));
            }
            source_etag = revision.headers.get(axum::http::header::ETAG).cloned();
            let revision_value: serde_json::Value = serde_json::from_slice(&revision.body)
                .map_err(|error| {
                    DriveTransferError::Invalid(format!("invalid revision metadata: {error}"))
                })?;
            size = revision_value
                .get("size")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse().ok());
            md5 = revision_value
                .get("md5Checksum")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            if let Some(revision_mime) =
                revision_value.get("mimeType").and_then(serde_json::Value::as_str)
            {
                mime_type = revision_mime.to_owned();
            }
            owned_revision_fingerprint = Some(format!(
                "revision:{revision_id}:{}:{}:{}",
                revision_value
                    .get("modifiedTime")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                size.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                md5.as_deref().unwrap_or("unknown")
            ));
            fingerprint_parts = vec!["revision", &file_id];
        }
        if size.is_some_and(|size| size > DRIVE_TRANSFER_MAX_BYTES) {
            return Err(DriveTransferError::TooLarge);
        }
        let kind = if source_mime == GOOGLE_VIDS_MIME {
            let requested_mime = match kind {
                TransferKind::Export { mime_type } => Some(mime_type),
                TransferKind::Blob => None,
                TransferKind::Revision { .. } => {
                    return Err(DriveTransferError::Invalid(
                        "Google Vids revisions must use the long-running download operation"
                            .to_owned(),
                    ));
                }
                TransferKind::Vids { .. } => {
                    return Err(DriveTransferError::Invalid(
                        "invalid nested Google Vids transfer".to_owned(),
                    ));
                }
            };
            if requested_mime.is_none() {
                mime_type = "video/mp4".to_owned();
            }
            size = None;
            md5 = None;
            let resource_key = value.get("resourceKey").and_then(serde_json::Value::as_str);
            let _permit = self.materialization.clone().acquire_owned().await.map_err(|_| {
                DriveTransferError::Invalid("transfer service is shutting down".to_owned())
            })?;
            let download_uri = start_long_running_download(
                service,
                &agent,
                &selector,
                &file_id,
                requested_mime.as_deref(),
                resource_key,
            )
            .await?;
            TransferKind::Vids { download_uri, response: None, buffered: Vec::new(), eof: false }
        } else {
            kind
        };
        if matches!(kind, TransferKind::Export { .. }) {
            size = None;
            md5 = None;
        }
        let source_fingerprint = if let Some(revision) = owned_revision_fingerprint {
            fingerprint(&[&revision])
        } else {
            fingerprint_parts.push(md5.as_deref().unwrap_or("unknown"));
            let size_text = size.map(|value| value.to_string()).unwrap_or_else(|| "unknown".into());
            fingerprint_parts.push(&size_text);
            fingerprint(&fingerprint_parts)
        };
        let transfer_id = ulid::Ulid::new().to_string();
        let resumable = matches!(kind, TransferKind::Blob | TransferKind::Revision { .. });
        let session = Session {
            agent,
            selector,
            file_id: file_id.clone(),
            size,
            source_etag,
            kind,
            cursor: 0,
            touched: Instant::now(),
        };
        let mut sessions = self.inner.lock().await;
        if sessions.len() >= MAX_TRANSFER_SESSIONS {
            return Err(DriveTransferError::Busy);
        }
        sessions.insert(transfer_id.clone(), Arc::new(Mutex::new(session)));
        drop(sessions);
        Ok(DriveTransferSessionInfo {
            transfer_id,
            file_id,
            name,
            mime_type,
            size_bytes: size,
            md5_checksum: md5,
            source_fingerprint,
            chunk_size: DRIVE_TRANSFER_CHUNK_BYTES,
            resumable,
        })
    }

    pub async fn chunk(
        &self,
        service: &ProxyService,
        agent: &str,
        selector: &str,
        request_id: String,
        transfer_id: &str,
        offset: u64,
    ) -> Result<DriveTransferChunk, DriveTransferError> {
        let session = self
            .inner
            .lock()
            .await
            .get(transfer_id)
            .cloned()
            .ok_or(DriveTransferError::NotFound)?;
        let mut session = session.lock().await;
        if session.agent != agent || session.selector != selector {
            return Err(DriveTransferError::NotFound);
        }
        if session.touched.elapsed() > SESSION_TTL {
            drop(session);
            self.inner.lock().await.remove(transfer_id);
            return Err(DriveTransferError::Expired);
        }
        if offset > DRIVE_TRANSFER_MAX_BYTES {
            return Err(DriveTransferError::TooLarge);
        }
        if session.size.is_some_and(|size| offset > size) {
            return Err(DriveTransferError::Invalid("offset exceeds file size".to_owned()));
        }
        if matches!(session.kind, TransferKind::Vids { .. }) {
            reauthorize_download(service, &session, request_id).await?;
            if session.size == Some(offset) {
                session.touched = Instant::now();
                return Ok(DriveTransferChunk {
                    bytes: Bytes::new(),
                    offset,
                    total_size: session.size,
                    complete: true,
                });
            }
            return vids_chunk(&mut session, offset).await;
        }
        if session.size == Some(offset) {
            reauthorize_download(service, &session, request_id).await?;
            session.touched = Instant::now();
            return Ok(DriveTransferChunk {
                bytes: Bytes::new(),
                offset,
                total_size: session.size,
                complete: true,
            });
        }
        if offset == DRIVE_TRANSFER_MAX_BYTES {
            return Err(DriveTransferError::TooLarge);
        }
        let (path, range, cap) = match &session.kind {
            TransferKind::Blob => (
                format!(
                    "files/{}?alt=media&supportsAllDrives=true",
                    urlencoding::encode(&session.file_id)
                ),
                true,
                DRIVE_TRANSFER_CHUNK_BYTES,
            ),
            TransferKind::Revision { revision_id } => (
                format!(
                    "files/{}/revisions/{}?alt=media&supportsAllDrives=true",
                    urlencoding::encode(&session.file_id),
                    urlencoding::encode(revision_id)
                ),
                true,
                DRIVE_TRANSFER_CHUNK_BYTES,
            ),
            TransferKind::Export { mime_type } => {
                if offset != 0 {
                    return Err(DriveTransferError::Invalid(
                        "exports are non-resumable".to_owned(),
                    ));
                }
                (
                    format!(
                        "files/{}/export?mimeType={}",
                        urlencoding::encode(&session.file_id),
                        urlencoding::encode(mime_type)
                    ),
                    false,
                    EXPORT_MAX_BYTES,
                )
            }
            TransferKind::Vids { .. } => {
                return Err(DriveTransferError::Invalid(
                    "Google Vids transfer was not routed to its stream".to_owned(),
                ));
            }
        };
        let mut headers = HeaderMap::new();
        if range {
            let end = offset.saturating_add(DRIVE_TRANSFER_CHUNK_BYTES as u64 - 1);
            headers.insert(
                "range",
                HeaderValue::from_str(&format!("bytes={offset}-{end}"))
                    .map_err(|_| DriveTransferError::Invalid("invalid byte range".to_owned()))?,
            );
            if let Some(etag) = &session.source_etag {
                headers.insert(axum::http::header::IF_MATCH, etag.clone());
            }
        }
        let response = service
            .fetch_raw_bounded(
                ProxyRequest {
                    service: selector.to_owned(),
                    scope: "drive.readonly".to_owned(),
                    resource: path.clone(),
                    method: Method::GET,
                    path,
                    headers,
                    body: Bytes::new(),
                    agent_id: agent.to_owned(),
                    request_id,
                },
                cap,
            )
            .await?;
        if range && response.status != StatusCode::PARTIAL_CONTENT {
            return Err(DriveTransferError::Download(format!(
                "content range request returned HTTP {} instead of 206",
                response.status
            )));
        }
        if !range && !response.status.is_success() {
            return Err(DriveTransferError::Denied(format!(
                "content request returned HTTP {}",
                response.status
            )));
        }
        if response.body.len() > cap {
            return Err(if response.body.len() as u64 > DRIVE_TRANSFER_MAX_BYTES {
                DriveTransferError::TooLarge
            } else {
                DriveTransferError::Invalid("Drive returned an oversized transfer chunk".to_owned())
            });
        }
        let total_size = if range {
            let parsed =
                parse_content_range(response.headers.get("content-range")).ok_or_else(|| {
                    DriveTransferError::Invalid("Drive returned no valid Content-Range".to_owned())
                })?;
            if parsed.start != offset
                || parsed.end < parsed.start
                || parsed.end.saturating_sub(parsed.start).saturating_add(1)
                    != response.body.len() as u64
            {
                return Err(DriveTransferError::Invalid(
                    "Drive returned a non-contiguous content range".to_owned(),
                ));
            }
            if let Some(expected) = session.size
                && parsed.total != expected
            {
                return Err(DriveTransferError::Invalid(
                    "Drive content size changed during transfer".to_owned(),
                ));
            }
            if session.size.is_none() {
                session.size = Some(parsed.total);
            }
            Some(parsed.total)
        } else {
            None
        };
        if total_size.is_some_and(|size| size > DRIVE_TRANSFER_MAX_BYTES) {
            return Err(DriveTransferError::TooLarge);
        }
        let next = offset.saturating_add(response.body.len() as u64);
        let complete = !range || total_size.is_some_and(|size| next == size);
        session.touched = Instant::now();
        Ok(DriveTransferChunk { bytes: response.body, offset, total_size, complete })
    }

    pub async fn cancel(
        &self,
        agent: &str,
        selector: &str,
        transfer_id: &str,
    ) -> Result<(), DriveTransferError> {
        let session = self
            .inner
            .lock()
            .await
            .get(transfer_id)
            .cloned()
            .ok_or(DriveTransferError::NotFound)?;
        let session = session.lock().await;
        if session.agent != agent || session.selector != selector {
            return Err(DriveTransferError::NotFound);
        }
        drop(session);
        self.inner.lock().await.remove(transfer_id);
        Ok(())
    }

    pub async fn materialization_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, DriveTransferError> {
        self.materialization.clone().acquire_owned().await.map_err(|_| {
            DriveTransferError::Invalid("transfer service is shutting down".to_owned())
        })
    }
}

impl ProxyService {
    pub async fn drive_transfer_start(
        &self,
        agent: String,
        selector: String,
        request_id: String,
        start: DriveTransferStart,
    ) -> Result<DriveTransferSessionInfo, DriveTransferError> {
        self.drive_transfers.start(self, agent, selector, request_id, start).await
    }

    pub async fn drive_transfer_chunk(
        &self,
        agent: &str,
        selector: &str,
        request_id: String,
        transfer_id: &str,
        offset: u64,
    ) -> Result<DriveTransferChunk, DriveTransferError> {
        let _permit = self.drive_transfers.materialization_permit().await?;
        let result = self
            .drive_transfers
            .chunk(self, agent, selector, request_id, transfer_id, offset)
            .await;
        if result.as_ref().is_ok_and(|chunk| chunk.complete) {
            self.drive_transfers.inner.lock().await.remove(transfer_id);
        }
        result
    }

    pub async fn drive_transfer_cancel(
        &self,
        agent: &str,
        selector: &str,
        transfer_id: &str,
    ) -> Result<(), DriveTransferError> {
        self.drive_transfers.cancel(agent, selector, transfer_id).await
    }
}

async fn reauthorize_download(
    service: &ProxyService,
    session: &Session,
    request_id: String,
) -> Result<(), DriveTransferError> {
    let path = format!(
        "files/{}?supportsAllDrives=true&fields=id,capabilities(canDownload)",
        urlencoding::encode(&session.file_id)
    );
    let response = service
        .handle(ProxyRequest {
            service: session.selector.clone(),
            scope: "drive.readonly".to_owned(),
            resource: path.clone(),
            method: Method::GET,
            path,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            agent_id: session.agent.clone(),
            request_id,
        })
        .await?;
    if !response.status.is_success() {
        return Err(DriveTransferError::Denied(format!(
            "authorization refresh returned HTTP {}",
            response.status
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&response.body).map_err(|error| {
        DriveTransferError::Invalid(format!("invalid authorization metadata: {error}"))
    })?;
    if value.pointer("/capabilities/canDownload").and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Err(DriveTransferError::Denied("capabilities.canDownload is false".to_owned()));
    }
    Ok(())
}

async fn start_long_running_download(
    service: &ProxyService,
    agent: &str,
    selector: &str,
    file_id: &str,
    mime_type: Option<&str>,
    resource_key: Option<&str>,
) -> Result<url::Url, DriveTransferError> {
    let mut headers = HeaderMap::new();
    if let Some(resource_key) = resource_key {
        let value = format!("{file_id}/{resource_key}");
        headers.insert(
            "x-goog-drive-resource-keys",
            HeaderValue::from_str(&value).map_err(|_| {
                DriveTransferError::Invalid("invalid Drive resource key".to_owned())
            })?,
        );
    }
    let query = mime_type
        .map(|mime_type| format!("?mimeType={}", urlencoding::encode(mime_type)))
        .unwrap_or_default();
    let path = format!("files/{}/download{query}", urlencoding::encode(file_id));
    let mut operation =
        fetch_operation(service, agent, selector, Method::POST, &path, &headers).await?;
    let started = Instant::now();
    let mut delay = Duration::from_secs(1);
    loop {
        if operation.get("done").and_then(serde_json::Value::as_bool) == Some(true) {
            if let Some(error) = operation.get("error") {
                let message = error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("the long-running download operation failed");
                return Err(DriveTransferError::Download(message.to_owned()));
            }
            let uri = operation
                .pointer("/response/downloadUri")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    DriveTransferError::Download(
                        "completed operation did not return a download URI".to_owned(),
                    )
                })?;
            return validate_signed_download_url(uri);
        }
        if started.elapsed() >= LRO_POLL_LIMIT {
            return Err(DriveTransferError::Download(
                "long-running download did not complete within 6 minutes".to_owned(),
            ));
        }
        let name = operation.get("name").and_then(serde_json::Value::as_str).ok_or_else(|| {
            DriveTransferError::Download(
                "pending operation did not return an operation name".to_owned(),
            )
        })?;
        let operation_id = name.strip_prefix("operations/").unwrap_or(name);
        validate_id(operation_id)?;
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
        let path = format!("operations/{}", urlencoding::encode(operation_id));
        operation = fetch_operation(service, agent, selector, Method::GET, &path, &headers).await?;
    }
}

async fn fetch_operation(
    service: &ProxyService,
    agent: &str,
    selector: &str,
    method: Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<serde_json::Value, DriveTransferError> {
    let response = service
        .fetch_raw(ProxyRequest {
            service: selector.to_owned(),
            scope: "drive.readonly".to_owned(),
            resource: path.to_owned(),
            method,
            path: path.to_owned(),
            headers: headers.clone(),
            body: Bytes::new(),
            agent_id: agent.to_owned(),
            request_id: ulid::Ulid::new().to_string(),
        })
        .await?;
    if !response.status.is_success() {
        return Err(DriveTransferError::Download(format!(
            "long-running operation returned HTTP {}",
            response.status
        )));
    }
    serde_json::from_slice(&response.body).map_err(|error| {
        DriveTransferError::Download(format!("invalid long-running operation response: {error}"))
    })
}

async fn vids_chunk(
    session: &mut Session,
    offset: u64,
) -> Result<DriveTransferChunk, DriveTransferError> {
    if offset != session.cursor {
        return Err(DriveTransferError::Invalid(
            "Google Vids downloads are non-resumable and require a contiguous offset".to_owned(),
        ));
    }
    let TransferKind::Vids { download_uri, response, buffered, eof } = &mut session.kind else {
        return Err(DriveTransferError::Invalid(
            "transfer is not a Google Vids download".to_owned(),
        ));
    };
    if response.is_none() {
        let opened = open_signed_download(download_uri.clone()).await?;
        if let Some(length) = opened.content_length() {
            if length > DRIVE_TRANSFER_MAX_BYTES {
                return Err(DriveTransferError::TooLarge);
            }
            session.size = Some(length);
        }
        *response = Some(Box::new(opened));
    }
    while buffered.len() < DRIVE_TRANSFER_CHUNK_BYTES && !*eof {
        let active_response = response.as_mut().ok_or_else(|| {
            DriveTransferError::Download("signed download response was not initialized".to_owned())
        })?;
        let next = active_response
            .chunk()
            .await
            .map_err(|error| DriveTransferError::Download(error.to_string()))?;
        match next {
            Some(bytes) => {
                let observed = session
                    .cursor
                    .saturating_add(buffered.len() as u64)
                    .saturating_add(bytes.len() as u64);
                if observed > DRIVE_TRANSFER_MAX_BYTES {
                    return Err(DriveTransferError::TooLarge);
                }
                buffered.extend_from_slice(&bytes);
            }
            None => *eof = true,
        }
    }
    let take = buffered.len().min(DRIVE_TRANSFER_CHUNK_BYTES);
    let bytes = Bytes::from(buffered.drain(..take).collect::<Vec<_>>());
    session.cursor = session.cursor.saturating_add(bytes.len() as u64);
    session.touched = Instant::now();
    let complete = (*eof && buffered.is_empty()) || session.size == Some(session.cursor);
    Ok(DriveTransferChunk { bytes, offset, total_size: session.size, complete })
}

async fn open_signed_download(mut url: url::Url) -> Result<reqwest::Response, DriveTransferError> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(2 * 60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| DriveTransferError::Download(error.to_string()))?;
    for _ in 0..=MAX_SIGNED_REDIRECTS {
        validate_signed_download_url(url.as_str())?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| DriveTransferError::Download(error.to_string()))?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    DriveTransferError::Download(
                        "signed download redirect had no valid Location".to_owned(),
                    )
                })?;
            url = url.join(location).map_err(|_| {
                DriveTransferError::Download("invalid signed download redirect".to_owned())
            })?;
            continue;
        }
        if !response.status().is_success() {
            return Err(DriveTransferError::Download(format!(
                "signed download returned HTTP {}",
                response.status()
            )));
        }
        if response.content_length().is_some_and(|length| length > DRIVE_TRANSFER_MAX_BYTES) {
            return Err(DriveTransferError::TooLarge);
        }
        return Ok(response);
    }
    Err(DriveTransferError::Download("signed download exceeded the redirect limit".to_owned()))
}

fn validate_signed_download_url(value: &str) -> Result<url::Url, DriveTransferError> {
    let url = url::Url::parse(value)
        .map_err(|_| DriveTransferError::Download("invalid signed download URL".to_owned()))?;
    let host = url.host_str().ok_or_else(|| {
        DriveTransferError::Download("signed download URL has no host".to_owned())
    })?;
    let google_host = host == "drive.usercontent.google.com"
        || host == "www.googleapis.com"
        || host.ends_with(".googleusercontent.com");
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || !google_host
    {
        return Err(DriveTransferError::Download(
            "signed download URL failed Google HTTPS validation".to_owned(),
        ));
    }
    Ok(url)
}

fn validate_id(value: &str) -> Result<(), DriveTransferError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(DriveTransferError::Invalid("invalid Drive resource ID".to_owned()));
    }
    Ok(())
}

struct ParsedContentRange {
    start: u64,
    end: u64,
    total: u64,
}

fn parse_content_range(header: Option<&HeaderValue>) -> Option<ParsedContentRange> {
    let value = header?.to_str().ok()?.strip_prefix("bytes ")?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some(ParsedContentRange {
        start: start.parse().ok()?,
        end: end.parse().ok()?,
        total: total.parse().ok()?,
    })
}

fn fingerprint(parts: &[&str]) -> String {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_download_url_accepts_only_google_https_hosts() {
        assert!(
            validate_signed_download_url("https://drive.usercontent.google.com/download?id=x")
                .is_ok()
        );
        assert!(
            validate_signed_download_url("https://doc-1.docs.googleusercontent.com/file").is_ok()
        );
        assert!(validate_signed_download_url("https://www.googleapis.com/download/file").is_ok());

        for rejected in [
            "http://drive.usercontent.google.com/download",
            "https://127.0.0.1/download",
            "https://evilgoogleusercontent.com/download",
            "https://user@drive.usercontent.google.com/download",
            "https://drive.usercontent.google.com:444/download",
        ] {
            assert!(validate_signed_download_url(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn content_range_is_parsed_strictly() -> Result<(), Box<dyn std::error::Error>> {
        let valid = HeaderValue::from_str("bytes 0-9/20")?;
        let wildcard = HeaderValue::from_str("bytes 0-9/*")?;
        let parsed = parse_content_range(Some(&valid)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "valid range did not parse")
        })?;
        assert_eq!((parsed.start, parsed.end, parsed.total), (0, 9, 20));
        assert!(parse_content_range(Some(&wildcard)).is_none());
        Ok(())
    }
}
