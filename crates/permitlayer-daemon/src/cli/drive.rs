//! Unprivileged Google Drive binary upload client.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "macos"))]
const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:3820";
const MAX_UPLOAD_BYTES: u64 = 250 * 1024 * 1024;
#[cfg(not(target_os = "macos"))]
const MAX_TOKEN_BYTES: u64 = 4096;

#[derive(Args, Debug)]
pub struct DriveArgs {
    #[command(subcommand)]
    pub command: DriveCommand,
}

#[derive(Subcommand, Debug)]
pub enum DriveCommand {
    /// Upload a local binary file to Google Drive.
    Upload(UploadArgs),
    /// Check an in-flight upload without creating another Drive file.
    UploadStatus(UploadStatusArgs),
    /// Abandon an in-flight upload session.
    UploadCancel(UploadStatusArgs),
}

#[derive(Args, Debug)]
pub struct UploadArgs {
    /// Local file to upload. Use `--` before paths beginning with `-`.
    pub path: PathBuf,
    /// Drive file name. Required when the local basename is not UTF-8.
    #[arg(long)]
    pub name: Option<String>,
    /// Parent Drive folder ID.
    #[arg(long)]
    pub parent: Option<String>,
    /// Content MIME type. Inferred from the file extension when omitted.
    #[arg(long = "mime-type")]
    pub mime_type: Option<String>,
    /// Drive connection alias, name, or ID.
    #[arg(long, default_value = "drive")]
    pub connection: String,
    /// Agent bearer-token file (non-macOS compatibility transport only).
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Emit one machine-readable result object on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct UploadStatusArgs {
    pub upload_id: String,
    #[arg(long, default_value = "drive")]
    pub connection: String,
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct StartRequest<'a> {
    name: &'a str,
    mime_type: &'a str,
    size_bytes: u64,
    parent_id: Option<&'a str>,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct StartResponse {
    agent: String,
    connection: String,
    upload_id: String,
    file_id: String,
    chunk_size: usize,
    size_bytes: u64,
    acknowledged_bytes: u64,
    completed: bool,
    file: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChunkResponse {
    state: String,
    acknowledged_bytes: Option<u64>,
    file: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
struct StatusResponse {
    upload_id: String,
    file_id: String,
    size_bytes: u64,
    acknowledged_bytes: u64,
    completed: bool,
    file: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    request_id: Option<String>,
}

struct UploadHttpResponse {
    status: axum::http::StatusCode,
    body: Vec<u8>,
}

pub async fn run(args: DriveArgs) -> Result<()> {
    match args.command {
        DriveCommand::Upload(args) => upload(args).await,
        DriveCommand::UploadStatus(args) => status(args).await,
        DriveCommand::UploadCancel(args) => cancel(args).await,
    }
}

async fn upload(args: UploadArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    let bearer_token: Option<String> = None;
    #[cfg(not(target_os = "macos"))]
    let bearer_token = Some(read_bearer_token(args.token_file.as_deref())?);
    let symlink_meta = std::fs::symlink_metadata(&args.path)
        .with_context(|| format!("cannot inspect {}", args.path.display()))?;
    if symlink_meta.file_type().is_symlink() || !symlink_meta.file_type().is_file() {
        bail!("upload path must be a regular, non-symlink file");
    }
    let mut file = std::fs::File::open(&args.path)
        .with_context(|| format!("cannot open {}", args.path.display()))?;
    let initial = file.metadata().context("cannot stat open upload file")?;
    if initial.len() > MAX_UPLOAD_BYTES {
        bail!("file is larger than the 250 MiB upload limit");
    }
    let name = match args.name {
        Some(name) => name,
        None => args
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .context("local basename is not UTF-8; provide --name")?,
    };
    let mime_type = args.mime_type.unwrap_or_else(|| {
        mime_guess::from_path(&args.path).first_or_octet_stream().essence_str().to_owned()
    });
    let _: mime::Mime = mime_type.parse().context("invalid --mime-type")?;

    let mut hasher = Md5::new();
    let mut hash_buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut hash_buffer).context("failed while hashing upload file")?;
        if read == 0 {
            break;
        }
        hasher.update(&hash_buffer[..read]);
    }
    let local_md5 = format!("{:x}", hasher.finalize());
    file.seek(SeekFrom::Start(0)).context("upload file is not seekable")?;
    ensure_file_unchanged(&initial, &file.metadata()?)?;

    let selector = urlencoding::encode(&args.connection);
    let start_path = format!("/v1/tools/{selector}/uploads");
    let start_request = StartRequest {
        name: &name,
        mime_type: &mime_type,
        size_bytes: initial.len(),
        parent_id: args.parent.as_deref(),
        idempotency_key: upload_idempotency_key(
            &local_md5,
            initial.len(),
            &name,
            &mime_type,
            args.parent.as_deref(),
        ),
    };
    let response = upload_http_request(
        axum::http::Method::POST,
        &start_path,
        Some("application/json"),
        None,
        serde_json::to_vec(&start_request)?,
        bearer_token.as_deref(),
    )
    .await?;
    let start: StartResponse = parse_response(response)?;
    if start.size_bytes != initial.len() {
        bail!("PermitLayer returned an inconsistent upload size");
    }
    if !args.json {
        eprintln!(
            "upload authorized for agent '{}' via connection '{}' (Drive file {})",
            start.agent, start.connection, start.file_id
        );
    }

    if start.acknowledged_bytes > initial.len() {
        bail!("PermitLayer returned an invalid acknowledged upload offset");
    }
    let mut final_file = start.file;
    let mut offset = start.acknowledged_bytes;
    let chunk_size = start.chunk_size.min(8 * 1024 * 1024);
    if !start.completed {
        if chunk_size == 0 || !chunk_size.is_multiple_of(256 * 1024) {
            bail!("PermitLayer returned an invalid Drive chunk size");
        }
        file.seek(SeekFrom::Start(offset))?;
        while offset < initial.len() {
            let remaining = initial.len() - offset;
            let wanted = remaining.min(chunk_size as u64) as usize;
            let mut chunk = vec![0_u8; wanted];
            file.read_exact(&mut chunk).context("upload file changed or became unreadable")?;
            let end = offset + wanted as u64 - 1;
            let upload_path =
                format!("/v1/tools/{selector}/uploads/{}", urlencoding::encode(&start.upload_id));
            let response = upload_http_request(
                axum::http::Method::PUT,
                &upload_path,
                Some("application/octet-stream"),
                Some(format!("bytes {offset}-{end}/{}", initial.len())),
                chunk,
                bearer_token.as_deref(),
            )
            .await
                .with_context(|| {
                    format!(
                        "upload interrupted; reconcile with `agentsso drive upload-status {} --connection {}`",
                        start.upload_id, args.connection
                    )
                })?;
            let status = response.status;
            let chunk: ChunkResponse = parse_response_allow_308(response)?;
            if status.as_u16() == 308 || chunk.state == "incomplete" {
                let acknowledged = chunk.acknowledged_bytes.context(
                    "PermitLayer returned an incomplete upload without an acknowledged offset",
                )?;
                if acknowledged <= offset || acknowledged > end + 1 {
                    bail!("PermitLayer returned an invalid acknowledged upload offset");
                }
                if acknowledged != end + 1 {
                    file.seek(SeekFrom::Start(acknowledged))?;
                }
                offset = acknowledged;
            } else if chunk.state == "complete" {
                final_file = chunk.file;
                offset = initial.len();
            } else {
                bail!("PermitLayer returned an unknown upload state");
            }
            if !args.json {
                eprintln!("uploaded {offset}/{} bytes", initial.len());
            }
        }
    }
    ensure_file_unchanged(&initial, &file.metadata()?)?;
    let file_json = final_file.context("Drive upload completed without file metadata")?;
    validate_drive_integrity(&file_json, initial.len(), &local_md5, &start.file_id)?;

    let result = serde_json::json!({
        "status": "uploaded",
        "agent": start.agent,
        "connection": start.connection,
        "upload_id": start.upload_id,
        "file": file_json,
        "local_md5": local_md5,
    });
    if args.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("✓ uploaded '{}' to Drive (id {})", name, start.file_id);
    }
    Ok(())
}

async fn status(args: UploadStatusArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    let bearer_token: Option<String> = None;
    #[cfg(not(target_os = "macos"))]
    let bearer_token = Some(read_bearer_token(args.token_file.as_deref())?);
    let path = upload_item_path(&args.connection, &args.upload_id);
    let response = upload_http_request(
        axum::http::Method::GET,
        &path,
        None,
        None,
        Vec::new(),
        bearer_token.as_deref(),
    )
    .await?;
    let status: StatusResponse = parse_response(response)?;
    if args.json {
        println!("{}", serde_json::to_string(&status)?);
    } else {
        println!(
            "upload {}: {} bytes acknowledged{}",
            status.upload_id,
            status.acknowledged_bytes,
            if status.completed { " (complete)" } else { "" }
        );
    }
    Ok(())
}

async fn cancel(args: UploadStatusArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    let bearer_token: Option<String> = None;
    #[cfg(not(target_os = "macos"))]
    let bearer_token = Some(read_bearer_token(args.token_file.as_deref())?);
    let response = upload_http_request(
        axum::http::Method::DELETE,
        &upload_item_path(&args.connection, &args.upload_id),
        None,
        None,
        Vec::new(),
        bearer_token.as_deref(),
    )
    .await?;
    if !response.status.is_success() {
        return Err(response_error(response));
    }
    if args.json {
        println!("{}", serde_json::json!({"status":"cancelled","upload_id":args.upload_id}));
    } else {
        println!("✓ upload session {} cancelled", args.upload_id);
    }
    Ok(())
}

fn upload_item_path(connection: &str, upload_id: &str) -> String {
    format!(
        "/v1/tools/{}/uploads/{}",
        urlencoding::encode(connection),
        urlencoding::encode(upload_id)
    )
}

#[cfg(not(target_os = "macos"))]
fn upload_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(6 * 60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to construct upload HTTP client")
}

#[cfg(not(target_os = "macos"))]
fn default_token_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine user home directory")?;
    Ok(home.join(".agentsso").join("agent-bearer.token"))
}

#[cfg(not(target_os = "macos"))]
fn read_bearer_token(path: Option<&std::path::Path>) -> Result<String> {
    let path = path.map(std::path::Path::to_path_buf).map_or_else(default_token_path, Ok)?;
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("cannot inspect bearer token file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("bearer token path must be a regular, non-symlink file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_TOKEN_BYTES {
        bail!("bearer token file has an invalid size");
    }
    let token = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read bearer token file {}", path.display()))?;
    let token = token.trim().to_owned();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        bail!("bearer token file contains an invalid token");
    }
    Ok(token)
}

fn ensure_file_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        bail!("local file changed during upload; Drive result must not be trusted");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("local file identity changed during upload");
        }
    }
    Ok(())
}

fn validate_drive_integrity(
    file: &serde_json::Value,
    expected_size: u64,
    expected_md5: &str,
    file_id: &str,
) -> Result<()> {
    let size = file["size"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| file["size"].as_u64())
        .context("Drive did not return a valid file size")?;
    let md5 = file["md5Checksum"].as_str().context("Drive did not return md5Checksum")?;
    if size != expected_size || !md5.eq_ignore_ascii_case(expected_md5) {
        bail!(
            "Drive integrity check failed for file {file_id}; expected {expected_size} bytes/{expected_md5}, received {size} bytes/{md5}. Inspect and delete that Drive file manually."
        );
    }
    Ok(())
}

fn upload_idempotency_key(
    md5: &str,
    size: u64,
    name: &str,
    mime_type: &str,
    parent_id: Option<&str>,
) -> String {
    let mut hasher = sha2::Sha256::new();
    for value in [md5, &size.to_string(), name, mime_type, parent_id.unwrap_or("")] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

async fn upload_http_request(
    method: axum::http::Method,
    path: &str,
    content_type: Option<&str>,
    content_range: Option<String>,
    body: Vec<u8>,
    bearer_token: Option<&str>,
) -> Result<UploadHttpResponse> {
    #[cfg(target_os = "macos")]
    {
        use http_body_util::BodyExt as _;
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        if bearer_token.is_some() {
            bail!("internal error: bearer authentication is disabled for macOS local uploads");
        }
        let uid = nix::unistd::geteuid().as_raw();
        let socket = permitlayer_core::paths::local_agent_socket_path(
            permitlayer_core::paths::home_override().as_deref(),
            uid,
        );
        let metadata = std::fs::symlink_metadata(&socket).with_context(|| {
            format!(
                "secretless upload socket {} is unavailable; ask an operator to run `sudo agentsso agent local-access grant <agent> --user <your-user>`",
                socket.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            bail!("local upload socket path is not a regular Unix socket");
        }
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            bail!(
                "local upload socket has unsafe ownership or permissions (expected uid {uid}, mode 0600)"
            );
        }
        let stream =
            tokio::time::timeout(Duration::from_secs(10), tokio::net::UnixStream::connect(&socket))
                .await
                .context("timed out connecting to the PermitLayer local upload socket")?
                .with_context(|| format!("connect to {}", socket.display()))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .context("start HTTP over the PermitLayer local upload socket")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(error = %error, "local upload HTTP connection ended with an error");
            }
        });

        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "permitlayer.local")
            .header("content-length", body.len());
        if let Some(value) = content_type {
            builder = builder.header("content-type", value);
        }
        if let Some(value) = content_range {
            builder = builder.header("content-range", value);
        }
        let request = builder.body(axum::body::Body::from(body)).context("build upload request")?;
        let response =
            tokio::time::timeout(Duration::from_secs(6 * 60), sender.send_request(request))
                .await
                .context("PermitLayer local upload request timed out")?
                .context("PermitLayer local upload request failed")?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .context("read PermitLayer local upload response")?
            .to_bytes()
            .to_vec();
        Ok(UploadHttpResponse { status, body })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let token = bearer_token.context("agent bearer token is required on this platform")?;
        let url = format!("{DEFAULT_DAEMON_URL}{path}");
        let mut request = upload_client()?
            .request(method, url)
            .bearer_auth(token)
            .header("x-agentsso-scope", "drive.file")
            .body(body);
        if let Some(value) = content_type {
            request = request.header("content-type", value);
        }
        if let Some(value) = content_range {
            request = request.header("content-range", value);
        }
        let response =
            request.send().await.context("PermitLayer upload endpoint is unreachable")?;
        let status = response.status();
        let body = response.bytes().await.context("read PermitLayer upload response")?.to_vec();
        Ok(UploadHttpResponse { status, body })
    }
}

fn parse_response<T: for<'de> Deserialize<'de>>(response: UploadHttpResponse) -> Result<T> {
    if !response.status.is_success() {
        return Err(response_error(response));
    }
    serde_json::from_slice(&response.body).context("invalid PermitLayer response")
}

fn parse_response_allow_308<T: for<'de> Deserialize<'de>>(
    response: UploadHttpResponse,
) -> Result<T> {
    if !response.status.is_success() && response.status.as_u16() != 308 {
        return Err(response_error(response));
    }
    serde_json::from_slice(&response.body).context("invalid PermitLayer upload response")
}

fn response_error(response: UploadHttpResponse) -> anyhow::Error {
    let status = response.status;
    match serde_json::from_slice::<ErrorEnvelope>(&response.body) {
        Ok(envelope) => {
            let request = envelope
                .error
                .request_id
                .filter(|value| !value.is_empty())
                .map(|value| format!("; request {value}"))
                .unwrap_or_default();
            anyhow::anyhow!(
                "PermitLayer {}: {} (HTTP {}{})",
                envelope.error.code,
                envelope.error.message,
                status.as_u16(),
                request
            )
        }
        Err(_) => anyhow::anyhow!("PermitLayer upload failed with HTTP {}", status.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_accepts_string_size() {
        let file = serde_json::json!({"size":"3","md5Checksum":"900150983cd24fb0d6963f7d28e17f72"});
        assert!(
            validate_drive_integrity(&file, 3, "900150983cd24fb0d6963f7d28e17f72", "id").is_ok()
        );
    }

    #[test]
    fn integrity_rejects_mismatch() {
        let file = serde_json::json!({"size":"4","md5Checksum":"bad"});
        assert!(validate_drive_integrity(&file, 3, "good", "id").is_err());
    }

    #[test]
    fn idempotency_key_includes_drive_metadata() {
        let first = upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", None);
        let renamed = upload_idempotency_key("abc", 3, "two.pdf", "application/pdf", None);
        let reparented =
            upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", Some("folder"));
        assert_ne!(first, renamed);
        assert_ne!(first, reparented);
        assert_eq!(first, upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", None));
    }
}
