//! Unprivileged Google Drive binary upload client.

use std::io::{Read, Seek, SeekFrom, Write};
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

macro_rules! transfer_token {
    ($args:expr) => {{
        #[cfg(target_os = "macos")]
        {
            None
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(read_bearer_token($args.token_file.as_deref())?)
        }
    }};
}

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
    /// Download a blob file without exposing Drive credentials.
    Download(DownloadArgs),
    /// Export a Google Workspace file to a binary format.
    Export(ExportArgs),
    /// Download a retained blob revision.
    RevisionDownload(RevisionDownloadArgs),
    /// Replace the bytes of an existing Drive file while preserving its ID.
    Replace(ReplaceArgs),
}

#[derive(Args, Debug)]
pub struct ReplaceArgs {
    pub file_id: String,
    pub path: PathBuf,
    #[arg(long = "mime-type")]
    pub mime_type: Option<String>,
    #[arg(long, default_value = "drive")]
    pub connection: String,
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DownloadArgs {
    pub file_id: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "drive")]
    pub connection: String,
    #[arg(long)]
    pub force: bool,
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    pub file_id: String,
    #[arg(long = "mime-type")]
    pub mime_type: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "drive")]
    pub connection: String,
    #[arg(long)]
    pub force: bool,
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RevisionDownloadArgs {
    pub file_id: String,
    pub revision_id: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "drive")]
    pub connection: String,
    #[arg(long)]
    pub force: bool,
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "token-file", value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
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
    #[arg(skip)]
    replace_file_id: Option<String>,
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
    replace_file_id: Option<&'a str>,
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

struct TransferHttpResponse {
    status: axum::http::StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
enum TransferStartRequest<'a> {
    Blob { file_id: &'a str },
    Export { file_id: &'a str, mime_type: &'a str },
    Revision { file_id: &'a str, revision_id: &'a str },
}

#[derive(Clone, Deserialize, Serialize)]
struct TransferStartResponse {
    transfer_id: String,
    file_id: String,
    name: String,
    mime_type: String,
    size_bytes: Option<u64>,
    md5_checksum: Option<String>,
    #[serde(default)]
    source_fingerprint: String,
    chunk_size: usize,
    resumable: bool,
}

#[derive(Deserialize, Serialize)]
struct TransferResumeState {
    schema_version: u16,
    request: serde_json::Value,
    connection: String,
    transfer: TransferStartResponse,
    offset: u64,
}

pub async fn run(args: DriveArgs) -> Result<()> {
    match args.command {
        DriveCommand::Upload(args) => upload(args).await,
        DriveCommand::UploadStatus(args) => status(args).await,
        DriveCommand::UploadCancel(args) => cancel(args).await,
        DriveCommand::Download(args) => {
            download_transfer(
                TransferStartRequest::Blob { file_id: &args.file_id },
                &args.output,
                &args.connection,
                args.force,
                args.json,
                transfer_token!(args),
            )
            .await
        }
        DriveCommand::Export(args) => {
            let _: mime::Mime = args.mime_type.parse().context("invalid --mime-type")?;
            download_transfer(
                TransferStartRequest::Export { file_id: &args.file_id, mime_type: &args.mime_type },
                &args.output,
                &args.connection,
                args.force,
                args.json,
                transfer_token!(args),
            )
            .await
        }
        DriveCommand::RevisionDownload(args) => {
            download_transfer(
                TransferStartRequest::Revision {
                    file_id: &args.file_id,
                    revision_id: &args.revision_id,
                },
                &args.output,
                &args.connection,
                args.force,
                args.json,
                transfer_token!(args),
            )
            .await
        }
        DriveCommand::Replace(args) => {
            let upload_args = UploadArgs {
                path: args.path,
                name: None,
                parent: None,
                mime_type: args.mime_type,
                connection: args.connection,
                #[cfg(not(target_os = "macos"))]
                token_file: args.token_file,
                json: args.json,
                replace_file_id: Some(args.file_id),
            };
            upload(upload_args).await
        }
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
    let collection = if args.replace_file_id.is_some() { "replacements" } else { "uploads" };
    let required_scope = if args.replace_file_id.is_some() { "drive.full" } else { "drive.file" };
    let start_path = format!("/v1/tools/{selector}/{collection}");
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
            args.replace_file_id.as_deref(),
        ),
        replace_file_id: args.replace_file_id.as_deref(),
    };
    let response = transfer_http_request(
        axum::http::Method::POST,
        &start_path,
        Some("application/json"),
        None,
        serde_json::to_vec(&start_request)?,
        bearer_token.as_deref(),
        required_scope,
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
            let upload_path = format!(
                "/v1/tools/{selector}/{collection}/{}",
                urlencoding::encode(&start.upload_id)
            );
            let response = transfer_http_request(
                axum::http::Method::PUT,
                &upload_path,
                Some("application/octet-stream"),
                Some(format!("bytes {offset}-{end}/{}", initial.len())),
                chunk,
                bearer_token.as_deref(),
                required_scope,
            )
            .await
                .with_context(|| {
                    if args.replace_file_id.is_some() {
                        "replacement interrupted; rerun the identical `agentsso drive replace` command to resume"
                            .to_owned()
                    } else {
                        format!(
                            "upload interrupted; reconcile with `agentsso drive upload-status {} --connection {}`",
                            start.upload_id, args.connection
                        )
                    }
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

    let operation = if args.replace_file_id.is_some() { "replaced" } else { "uploaded" };
    let result = serde_json::json!({
        "status": operation,
        "agent": start.agent,
        "connection": start.connection,
        "upload_id": start.upload_id,
        "file": file_json,
        "local_md5": local_md5,
    });
    if args.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("✓ {operation} '{}' in Drive (id {})", name, start.file_id);
    }
    Ok(())
}

async fn download_transfer(
    start_request: TransferStartRequest<'_>,
    output: &std::path::Path,
    connection: &str,
    force: bool,
    json: bool,
    bearer_token: Option<String>,
) -> Result<()> {
    let request_value = serde_json::to_value(&start_request)?;
    if let Ok(metadata) = std::fs::symlink_metadata(output) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!("download destination must be a regular, non-symlink file");
        }
        if !force {
            bail!("download destination already exists; pass --force to replace it");
        }
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let parent_meta = std::fs::symlink_metadata(parent)
        .with_context(|| format!("cannot inspect destination directory {}", parent.display()))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!("download destination parent must be a regular, non-symlink directory");
    }
    let selector = urlencoding::encode(connection);
    let collection_path = format!("/v1/tools/{selector}/downloads");
    let (partial_path, resume_path) = transfer_resume_paths(output)?;
    let partial_exists = std::fs::symlink_metadata(&partial_path).is_ok();
    let mut resume_exists = std::fs::symlink_metadata(&resume_path).is_ok();
    if !partial_exists && resume_exists && output.is_file() {
        std::fs::remove_file(&resume_path)
            .context("remove stale completed download resume metadata")?;
        resume_exists = false;
    }
    if partial_exists != resume_exists {
        bail!(
            "incomplete Drive resume state beside {}; remove both {} and {} before retrying",
            output.display(),
            partial_path.display(),
            resume_path.display()
        );
    }
    let mut resume = if partial_exists {
        load_transfer_resume(&resume_path, &partial_path, &request_value, connection)?
    } else {
        let start =
            start_drive_transfer(&collection_path, &start_request, bearer_token.as_deref()).await?;
        let state = TransferResumeState {
            schema_version: 1,
            request: request_value.clone(),
            connection: connection.to_owned(),
            transfer: start,
            offset: 0,
        };
        let file = open_transfer_partial(&partial_path, true)
            .with_context(|| format!("create download partial file {}", partial_path.display()))?;
        drop(file);
        persist_transfer_resume(&resume_path, &state)?;
        state
    };
    if !resume.transfer.resumable && resume.offset != 0 {
        std::fs::remove_file(&partial_path).context("discard interrupted non-resumable export")?;
        std::fs::remove_file(&resume_path).context("discard export resume metadata")?;
        let start =
            start_drive_transfer(&collection_path, &start_request, bearer_token.as_deref()).await?;
        resume = TransferResumeState {
            schema_version: 1,
            request: request_value,
            connection: connection.to_owned(),
            transfer: start,
            offset: 0,
        };
        let file =
            open_transfer_partial(&partial_path, true).context("recreate export partial file")?;
        drop(file);
        persist_transfer_resume(&resume_path, &resume)?;
    }
    validate_transfer_start(&resume.transfer)?;
    let mut partial = open_transfer_partial(&partial_path, false)
        .with_context(|| format!("open download partial file {}", partial_path.display()))?;
    let mut sha256 = sha2::Sha256::new();
    let mut md5 = Md5::new();
    hash_existing_partial(&mut partial, &mut sha256, &mut md5)?;
    let mut offset = resume.offset;
    partial.seek(SeekFrom::Start(offset))?;
    loop {
        let item_path = format!(
            "/v1/tools/{selector}/downloads/{}?offset={offset}",
            urlencoding::encode(&resume.transfer.transfer_id)
        );
        let mut response = transfer_http_request(
            axum::http::Method::GET,
            &item_path,
            None,
            None,
            Vec::new(),
            bearer_token.as_deref(),
            "drive.readonly",
        )
        .await?;
        if resume.transfer.resumable
            && matches!(
                response.status,
                axum::http::StatusCode::NOT_FOUND | axum::http::StatusCode::GONE
            )
        {
            let restarted =
                start_drive_transfer(&collection_path, &start_request, bearer_token.as_deref())
                    .await?;
            validate_transfer_start(&restarted)?;
            if !same_resume_source(&resume.transfer, &restarted) {
                bail!(
                    "Drive source changed since this partial download was created; remove {} and {} to restart safely",
                    partial_path.display(),
                    resume_path.display()
                );
            }
            resume.transfer = restarted;
            persist_transfer_resume(&resume_path, &resume)?;
            let item_path = format!(
                "/v1/tools/{selector}/downloads/{}?offset={offset}",
                urlencoding::encode(&resume.transfer.transfer_id)
            );
            response = transfer_http_request(
                axum::http::Method::GET,
                &item_path,
                None,
                None,
                Vec::new(),
                bearer_token.as_deref(),
                "drive.readonly",
            )
            .await?;
        }
        if !response.status.is_success() {
            return Err(response_error(response));
        }
        let returned_offset = response
            .headers
            .get("x-permitlayer-offset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .context("PermitLayer returned no valid transfer offset")?;
        if returned_offset != offset {
            bail!("PermitLayer returned a non-contiguous transfer chunk");
        }
        if response.body.len() > resume.transfer.chunk_size && resume.transfer.resumable {
            bail!("PermitLayer returned an oversized transfer chunk");
        }
        offset =
            offset.checked_add(response.body.len() as u64).context("download size overflow")?;
        if offset > MAX_UPLOAD_BYTES {
            bail!("Drive file is larger than the 250 MiB transfer limit");
        }
        partial.write_all(&response.body).context("write download partial file")?;
        sha256.update(&response.body);
        md5.update(&response.body);
        partial.sync_data().context("sync download partial file")?;
        resume.offset = offset;
        persist_transfer_resume(&resume_path, &resume)?;
        let complete =
            response.headers.get("x-permitlayer-complete").and_then(|value| value.to_str().ok())
                == Some("true");
        if !json {
            eprintln!("downloaded {offset} bytes");
        }
        if complete {
            break;
        }
        if response.body.is_empty() {
            bail!("PermitLayer returned an empty incomplete transfer chunk");
        }
    }
    if let Some(expected) = resume.transfer.size_bytes
        && expected != offset
    {
        bail!("Drive size check failed: expected {expected} bytes, received {offset}");
    }
    let local_md5 = format!("{:x}", md5.finalize());
    if let Some(expected) = &resume.transfer.md5_checksum
        && !expected.eq_ignore_ascii_case(&local_md5)
    {
        bail!("Drive MD5 check failed; destination was not installed");
    }
    let local_sha256 = format!("{:x}", sha256.finalize());
    partial.sync_all().context("sync downloaded file")?;
    drop(partial);
    install_transfer_partial(&partial_path, output, force)?;
    if let Err(error) = std::fs::remove_file(&resume_path) {
        eprintln!(
            "warning: downloaded file was installed, but stale resume metadata could not be removed: {error}"
        );
    }
    let result = serde_json::json!({
        "status": "downloaded",
        "file_id": resume.transfer.file_id,
        "name": resume.transfer.name,
        "mime_type": resume.transfer.mime_type,
        "output": output,
        "size_bytes": offset,
        "sha256": local_sha256,
        "md5": local_md5,
    });
    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("✓ downloaded '{}' to {}", resume.transfer.name, output.display());
        println!("  sha256: {local_sha256}");
    }
    Ok(())
}

async fn start_drive_transfer(
    collection_path: &str,
    request: &TransferStartRequest<'_>,
    bearer_token: Option<&str>,
) -> Result<TransferStartResponse> {
    let response = transfer_http_request(
        axum::http::Method::POST,
        collection_path,
        Some("application/json"),
        None,
        serde_json::to_vec(request)?,
        bearer_token,
        "drive.readonly",
    )
    .await?;
    let start: TransferStartResponse = parse_response(response)?;
    validate_transfer_start(&start)?;
    Ok(start)
}

fn validate_transfer_start(start: &TransferStartResponse) -> Result<()> {
    if start.chunk_size == 0 || start.chunk_size > 8 * 1024 * 1024 {
        bail!("PermitLayer returned an invalid transfer chunk size");
    }
    if start.size_bytes.is_some_and(|size| size > MAX_UPLOAD_BYTES) {
        bail!("Drive file is larger than the 250 MiB transfer limit");
    }
    Ok(())
}

fn same_resume_source(previous: &TransferStartResponse, restarted: &TransferStartResponse) -> bool {
    !previous.source_fingerprint.is_empty()
        && previous.source_fingerprint == restarted.source_fingerprint
        && previous.file_id == restarted.file_id
}

fn transfer_resume_paths(output: &std::path::Path) -> Result<(PathBuf, PathBuf)> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = output.file_name().context("download output must have a filename")?;
    let mut partial_name = std::ffi::OsString::from(".");
    partial_name.push(name);
    partial_name.push(".agentsso.part");
    let mut resume_name = std::ffi::OsString::from(".");
    resume_name.push(name);
    resume_name.push(".agentsso.resume.json");
    Ok((parent.join(partial_name), parent.join(resume_name)))
}

fn load_transfer_resume(
    resume_path: &std::path::Path,
    partial_path: &std::path::Path,
    request: &serde_json::Value,
    connection: &str,
) -> Result<TransferResumeState> {
    let resume_meta = std::fs::symlink_metadata(resume_path)
        .with_context(|| format!("inspect resume metadata {}", resume_path.display()))?;
    if resume_meta.file_type().is_symlink()
        || !resume_meta.file_type().is_file()
        || resume_meta.len() > 64 * 1024
    {
        bail!("download resume metadata must be a bounded regular, non-symlink file");
    }
    let partial_meta = std::fs::symlink_metadata(partial_path)
        .with_context(|| format!("inspect partial download {}", partial_path.display()))?;
    if partial_meta.file_type().is_symlink() || !partial_meta.file_type().is_file() {
        bail!("partial download must be a regular, non-symlink file");
    }
    let mut resume_file = open_transfer_readonly(resume_path)
        .with_context(|| format!("open resume metadata {}", resume_path.display()))?;
    let mut resume_bytes = Vec::new();
    std::io::Read::take(&mut resume_file, 64 * 1024 + 1)
        .read_to_end(&mut resume_bytes)
        .context("read download resume metadata")?;
    if resume_bytes.len() > 64 * 1024 {
        bail!("download resume metadata exceeds 64 KiB");
    }
    let state: TransferResumeState =
        serde_json::from_slice(&resume_bytes).context("invalid download resume metadata")?;
    if state.schema_version != 1 || &state.request != request || state.connection != connection {
        bail!(
            "existing partial download belongs to a different Drive request; remove {} and {} before retrying",
            partial_path.display(),
            resume_path.display()
        );
    }
    if state.offset != partial_meta.len() || state.offset > MAX_UPLOAD_BYTES {
        bail!("partial download length does not match its resume metadata");
    }
    Ok(state)
}

fn persist_transfer_resume(path: &std::path::Path, state: &TransferResumeState) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.file_type().is_file())
    {
        bail!("download resume metadata path is not a regular file");
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("create atomic download resume metadata")?;
    temporary.write_all(&serde_json::to_vec(state)?).context("write download resume metadata")?;
    temporary.as_file().sync_all().context("sync download resume metadata")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("install download resume metadata")?;
    Ok(())
}

fn hash_existing_partial(
    file: &mut std::fs::File,
    sha256: &mut sha2::Sha256,
    md5: &mut Md5,
) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).context("read existing download partial file")?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
        md5.update(&buffer[..read]);
    }
    Ok(())
}

fn open_transfer_partial(path: &std::path::Path, create_new: bool) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("transfer partial is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

fn open_transfer_readonly(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        bail!("transfer metadata is not a regular file");
    }
    Ok(file)
}

fn install_transfer_partial(
    partial: &std::path::Path,
    output: &std::path::Path,
    force: bool,
) -> Result<()> {
    if force {
        #[cfg(not(windows))]
        std::fs::rename(partial, output)
            .with_context(|| format!("atomically replace {}", output.display()))?;
        #[cfg(windows)]
        {
            if output.exists() {
                atomic_replace_windows(partial, output)?;
            } else {
                std::fs::rename(partial, output)
                    .with_context(|| format!("install {}", output.display()))?;
            }
        }
    } else {
        std::fs::hard_link(partial, output).with_context(|| {
            format!("atomically install {} without overwriting", output.display())
        })?;
        std::fs::remove_file(partial).context("remove completed partial download link")?;
    }
    Ok(())
}

#[cfg(windows)]
fn atomic_replace_windows(partial: &std::path::Path, output: &std::path::Path) -> Result<()> {
    permitlayer_platform_windows::replace_file(partial, output)
        .with_context(|| format!("atomically replace {}", output.display()))
}

async fn status(args: UploadStatusArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    let bearer_token: Option<String> = None;
    #[cfg(not(target_os = "macos"))]
    let bearer_token = Some(read_bearer_token(args.token_file.as_deref())?);
    let path = upload_item_path(&args.connection, &args.upload_id);
    let response = transfer_http_request(
        axum::http::Method::GET,
        &path,
        None,
        None,
        Vec::new(),
        bearer_token.as_deref(),
        "drive.file",
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
    let response = transfer_http_request(
        axum::http::Method::DELETE,
        &upload_item_path(&args.connection, &args.upload_id),
        None,
        None,
        Vec::new(),
        bearer_token.as_deref(),
        "drive.file",
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
    replace_file_id: Option<&str>,
) -> String {
    let mut hasher = sha2::Sha256::new();
    for value in [
        md5,
        &size.to_string(),
        name,
        mime_type,
        parent_id.unwrap_or(""),
        replace_file_id.unwrap_or(""),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

async fn transfer_http_request(
    method: axum::http::Method,
    path: &str,
    content_type: Option<&str>,
    content_range: Option<String>,
    body: Vec<u8>,
    bearer_token: Option<&str>,
    required_scope: &str,
) -> Result<TransferHttpResponse> {
    #[cfg(target_os = "macos")]
    {
        use http_body_util::BodyExt as _;
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        if bearer_token.is_some() {
            bail!("internal error: bearer authentication is disabled for macOS local transfers");
        }
        let uid = nix::unistd::geteuid().as_raw();
        let capability = match required_scope {
            "drive.readonly" => "drive-download",
            "drive.full" => "drive-replace",
            _ => "drive-upload",
        };
        let socket = permitlayer_core::paths::local_agent_socket_path(
            permitlayer_core::paths::home_override().as_deref(),
            uid,
        );
        let metadata = std::fs::symlink_metadata(&socket).with_context(|| {
            format!(
                "secretless transfer socket {} is unavailable; ask an operator to run `sudo agentsso agent local-access grant <agent> --user <your-user> --capability {capability}`",
                socket.display(),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            bail!("local transfer socket path is not a regular Unix socket");
        }
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            bail!(
                "local transfer socket has unsafe ownership or permissions (expected uid {uid}, mode 0600)"
            );
        }
        let stream =
            tokio::time::timeout(Duration::from_secs(10), tokio::net::UnixStream::connect(&socket))
                .await
                .context("timed out connecting to the PermitLayer local transfer socket")?
                .with_context(|| format!("connect to {}", socket.display()))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .context("start HTTP over the PermitLayer local transfer socket")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(error = %error, "local transfer HTTP connection ended with an error");
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
        let request =
            builder.body(axum::body::Body::from(body)).context("build transfer request")?;
        let response =
            tokio::time::timeout(Duration::from_secs(6 * 60), sender.send_request(request))
                .await
                .context("PermitLayer local transfer request timed out")?
                .context("PermitLayer local transfer request failed")?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .context("read PermitLayer local transfer response")?
            .to_bytes()
            .to_vec();
        Ok(TransferHttpResponse { status, headers, body })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let token = bearer_token.context("agent bearer token is required on this platform")?;
        let url = format!("{DEFAULT_DAEMON_URL}{path}");
        let mut request = upload_client()?
            .request(method, url)
            .bearer_auth(token)
            .header("x-agentsso-scope", required_scope)
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
        let headers = response.headers().clone();
        let body = response.bytes().await.context("read PermitLayer upload response")?.to_vec();
        Ok(TransferHttpResponse { status, headers, body })
    }
}

fn parse_response<T: for<'de> Deserialize<'de>>(response: TransferHttpResponse) -> Result<T> {
    if !response.status.is_success() {
        return Err(response_error(response));
    }
    serde_json::from_slice(&response.body).context("invalid PermitLayer response")
}

fn parse_response_allow_308<T: for<'de> Deserialize<'de>>(
    response: TransferHttpResponse,
) -> Result<T> {
    if !response.status.is_success() && response.status.as_u16() != 308 {
        return Err(response_error(response));
    }
    serde_json::from_slice(&response.body).context("invalid PermitLayer upload response")
}

fn response_error(response: TransferHttpResponse) -> anyhow::Error {
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

    fn resume_state(
        request: serde_json::Value,
        connection: &str,
        offset: u64,
    ) -> TransferResumeState {
        TransferResumeState {
            schema_version: 1,
            request,
            connection: connection.to_owned(),
            transfer: TransferStartResponse {
                transfer_id: "01TESTTRANSFER".to_owned(),
                file_id: "file-id".to_owned(),
                name: "template.xlsx".to_owned(),
                mime_type: "application/octet-stream".to_owned(),
                size_bytes: Some(offset),
                md5_checksum: None,
                source_fingerprint: "source".to_owned(),
                chunk_size: 8 * 1024 * 1024,
                resumable: true,
            },
            offset,
        }
    }

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
        let first = upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", None, None);
        let renamed = upload_idempotency_key("abc", 3, "two.pdf", "application/pdf", None, None);
        let reparented =
            upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", Some("folder"), None);
        let replaced =
            upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", None, Some("target"));
        assert_ne!(first, renamed);
        assert_ne!(first, reparented);
        assert_ne!(first, replaced);
        assert_eq!(
            first,
            upload_idempotency_key("abc", 3, "one.pdf", "application/pdf", None, None)
        );
    }

    #[test]
    fn resume_state_round_trips_across_invocations() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("report.xlsx");
        let (partial, resume) = transfer_resume_paths(&output)?;
        std::fs::write(&partial, b"partial")?;
        let request = serde_json::json!({"kind":"blob","file_id":"file-id"});
        let state = resume_state(request.clone(), "drive", 7);
        persist_transfer_resume(&resume, &state)?;

        let loaded = load_transfer_resume(&resume, &partial, &request, "drive")?;
        assert_eq!(loaded.offset, 7);
        assert_eq!(loaded.transfer.transfer_id, "01TESTTRANSFER");
        Ok(())
    }

    #[test]
    fn resume_state_rejects_a_different_request() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("report.xlsx");
        let (partial, resume) = transfer_resume_paths(&output)?;
        std::fs::write(&partial, b"partial")?;
        let state = resume_state(serde_json::json!({"kind":"blob","file_id":"one"}), "drive", 7);
        persist_transfer_resume(&resume, &state)?;

        let error = load_transfer_resume(
            &resume,
            &partial,
            &serde_json::json!({"kind":"blob","file_id":"two"}),
            "drive",
        );
        assert!(error.is_err());
        Ok(())
    }

    #[test]
    fn resume_requires_same_source_fingerprint() {
        let prior =
            resume_state(serde_json::json!({"kind":"blob","file_id":"file-id"}), "drive", 3)
                .transfer;
        let mut restarted = prior.clone();
        assert!(same_resume_source(&prior, &restarted));
        restarted.source_fingerprint = "different".to_owned();
        assert!(!same_resume_source(&prior, &restarted));
    }

    #[test]
    fn completed_partial_does_not_clobber_without_force() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let partial = directory.path().join("partial");
        let output = directory.path().join("output");
        std::fs::write(&partial, b"new")?;
        std::fs::write(&output, b"old")?;
        assert!(install_transfer_partial(&partial, &output, false).is_err());
        assert_eq!(std::fs::read(&output)?, b"old");
        assert_eq!(std::fs::read(&partial)?, b"new");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_transfer_partial_is_private() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let partial = directory.path().join("partial");
        let file = open_transfer_partial(&partial, true)?;
        assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
