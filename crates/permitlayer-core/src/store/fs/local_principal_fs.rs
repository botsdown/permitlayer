//! Filesystem-backed root-owned local-principal authorization store.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::agent::validate_agent_name;
use crate::store::error::StoreError;
use crate::store::local_principal::{
    LOCAL_PRINCIPAL_SCHEMA_VERSION, LocalPrincipal, LocalPrincipalStore,
};

const MAX_RECORD_BYTES: usize = 16 * 1024;
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One-file-per-UID store beneath `<state>/local-principals/`.
pub struct LocalPrincipalFsStore {
    home: PathBuf,
    mutation_lock: tokio::sync::Mutex<()>,
}

impl LocalPrincipalFsStore {
    /// Create/open the root-private local-principal namespace.
    pub fn new(home: PathBuf) -> Result<Self, StoreError> {
        super::create_restricted_dir(&home.join("local-principals"), "local-principals")?;
        Ok(Self { home, mutation_lock: tokio::sync::Mutex::new(()) })
    }

    /// Open an existing namespace without creating or chmodding anything.
    /// Used by read-only diagnostics.
    pub fn open_existing(home: PathBuf) -> Result<Self, StoreError> {
        let dir = home.join("local-principals");
        let metadata = std::fs::symlink_metadata(&dir).map_err(StoreError::IoError)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StoreError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "local-principals path is not a regular directory",
            )));
        }
        Ok(Self { home, mutation_lock: tokio::sync::Mutex::new(()) })
    }

    fn dir(&self) -> PathBuf {
        self.home.join("local-principals")
    }

    fn target(&self, uid: u32) -> PathBuf {
        self.dir().join(format!("{uid}.toml"))
    }

    fn tempfile(&self, uid: u32) -> PathBuf {
        let pid = std::process::id();
        let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.dir().join(format!("{uid}.toml.tmp.{pid}.{counter}"))
    }
}

#[async_trait]
impl LocalPrincipalStore for LocalPrincipalFsStore {
    async fn grant(&self, principal: LocalPrincipal) -> Result<(), StoreError> {
        validate_record(&principal)?;
        let _guard = self.mutation_lock.lock().await;
        let target = self.target(principal.uid);
        if let Some(existing) = read_record(&target, principal.uid).await? {
            return Err(StoreError::LocalPrincipalAlreadyExists {
                uid: principal.uid,
                agent: existing.agent,
            });
        }
        let tmp = self.tempfile(principal.uid);
        let dir = self.dir();
        let bytes = toml::to_string_pretty(&principal)
            .map_err(|error| StoreError::RecordSerdeFailed {
                kind: "local-principal",
                id: principal.uid.to_string(),
                reason: error.to_string(),
                source: Some(Box::new(error)),
            })?
            .into_bytes();
        tokio::task::spawn_blocking(move || super::atomic_write(&tmp, &target, &dir, &bytes))
            .await??;
        Ok(())
    }

    async fn replace(&self, principal: LocalPrincipal) -> Result<(), StoreError> {
        validate_record(&principal)?;
        let _guard = self.mutation_lock.lock().await;
        let target = self.target(principal.uid);
        if read_record(&target, principal.uid).await?.is_none() {
            return Err(StoreError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "local-principal grant does not exist",
            )));
        }
        let tmp = self.tempfile(principal.uid);
        let dir = self.dir();
        let bytes = toml::to_string_pretty(&principal)
            .map_err(|error| StoreError::RecordSerdeFailed {
                kind: "local-principal",
                id: principal.uid.to_string(),
                reason: error.to_string(),
                source: Some(Box::new(error)),
            })?
            .into_bytes();
        tokio::task::spawn_blocking(move || super::atomic_write(&tmp, &target, &dir, &bytes))
            .await??;
        Ok(())
    }

    async fn get(&self, uid: u32) -> Result<Option<LocalPrincipal>, StoreError> {
        read_record(&self.target(uid), uid).await
    }

    async fn list(&self) -> Result<Vec<LocalPrincipal>, StoreError> {
        let dir = self.dir();
        tokio::task::spawn_blocking(move || -> Result<Vec<LocalPrincipal>, StoreError> {
            let mut records = Vec::new();
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(records),
                Err(error) => return Err(StoreError::IoError(error)),
            };
            for entry in entries {
                let entry = entry.map_err(StoreError::IoError)?;
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(stem) = name.strip_suffix(".toml") else {
                    continue;
                };
                if stem.contains(".tmp.") {
                    continue;
                }
                let Ok(uid) = stem.parse::<u32>() else {
                    tracing::warn!(path = %path.display(), "skipping malformed local-principal filename");
                    continue;
                };
                match read_record_blocking(&path, uid) {
                    Ok(Some(record)) => records.push(record),
                    Ok(None) => {}
                    Err(error) => tracing::warn!(path = %path.display(), error = %error, "skipping malformed local-principal record"),
                }
            }
            records.sort_by_key(|record| record.uid);
            Ok(records)
        })
        .await?
    }

    async fn revoke(&self, uid: u32) -> Result<bool, StoreError> {
        let _guard = self.mutation_lock.lock().await;
        let target = self.target(uid);
        tokio::task::spawn_blocking(move || match std::fs::remove_file(target) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StoreError::IoError(error)),
        })
        .await?
    }
}

async fn read_record(path: &Path, uid: u32) -> Result<Option<LocalPrincipal>, StoreError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || read_record_blocking(&path, uid)).await?
}

fn read_record_blocking(path: &Path, uid: u32) -> Result<Option<LocalPrincipal>, StoreError> {
    let path_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::IoError(error)),
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal record is not a regular non-symlink file",
        )));
    }
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::IoError(error)),
    };
    let metadata = file.metadata().map_err(StoreError::IoError)?;
    if !metadata.is_file() {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal record is not a regular file",
        )));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(StoreError::IoError)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal record exceeds size limit",
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| StoreError::RecordSerdeFailed {
        kind: "local-principal",
        id: uid.to_string(),
        reason: error.to_string(),
        source: Some(Box::new(error)),
    })?;
    let record: LocalPrincipal =
        toml::from_str(text).map_err(|error| StoreError::RecordSerdeFailed {
            kind: "local-principal",
            id: uid.to_string(),
            reason: error.to_string(),
            source: Some(Box::new(error)),
        })?;
    if record.uid != uid {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal UID does not match filename",
        )));
    }
    validate_record(&record)?;
    Ok(Some(record))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::items_after_test_module)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn principal(uid: u32, user: &str, agent: &str) -> LocalPrincipal {
        LocalPrincipal {
            schema_version: LOCAL_PRINCIPAL_SCHEMA_VERSION,
            platform: "macos".to_owned(),
            uid,
            username_at_grant: user.to_owned(),
            agent: agent.to_owned(),
            capabilities: vec![crate::store::LocalCapability::DriveUpload],
            granted_at: Utc::now(),
            granted_by_peer_uid: Some(0),
        }
    }

    #[test]
    fn version_one_record_migrates_to_upload_only() {
        let record: LocalPrincipal = toml::from_str(
            r#"
schema_version = 1
platform = "macos"
uid = 501
username_at_grant = "angie"
agent = "drive-agent"
granted_at = "2026-07-30T12:00:00Z"
"#,
        )
        .unwrap();
        assert_eq!(record.capabilities, vec![crate::store::LocalCapability::DriveUpload]);
        assert!(validate_record(&record).is_ok());
        assert!(!record.permits(crate::store::LocalCapability::DriveDownload));
        assert!(!record.permits(crate::store::LocalCapability::DriveReplace));
    }

    #[test]
    fn version_two_missing_capabilities_fails_closed() {
        let record: LocalPrincipal = toml::from_str(
            r#"
schema_version = 2
platform = "macos"
uid = 501
username_at_grant = "angie"
agent = "drive-agent"
granted_at = "2026-07-30T12:00:00Z"
"#,
        )
        .unwrap();
        assert!(record.capabilities.is_empty());
        assert!(validate_record(&record).is_err());
    }

    #[test]
    fn version_one_cannot_claim_new_capabilities() {
        let record: LocalPrincipal = toml::from_str(
            r#"
schema_version = 1
platform = "macos"
uid = 501
username_at_grant = "angie"
agent = "drive-agent"
capabilities = ["drive-download"]
granted_at = "2026-07-30T12:00:00Z"
"#,
        )
        .unwrap();
        assert!(validate_record(&record).is_err());
    }

    #[tokio::test]
    async fn grant_list_get_and_revoke_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalPrincipalFsStore::new(temp.path().to_path_buf()).unwrap();
        store.grant(principal(502, "two", "hermes-two")).await.unwrap();
        store.grant(principal(501, "one", "hermes-one")).await.unwrap();

        assert_eq!(store.get(501).await.unwrap().unwrap().agent, "hermes-one");
        let listed = store.list().await.unwrap();
        assert_eq!(listed.iter().map(|p| p.uid).collect::<Vec<_>>(), vec![501, 502]);
        assert!(store.revoke(501).await.unwrap());
        assert!(!store.revoke(501).await.unwrap());
        assert!(store.get(501).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn grant_never_overwrites_an_existing_uid() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalPrincipalFsStore::new(temp.path().to_path_buf()).unwrap();
        store.grant(principal(501, "angie", "angie")).await.unwrap();
        let error = store.grant(principal(501, "angie", "other-agent")).await.unwrap_err();
        assert!(matches!(error, StoreError::LocalPrincipalAlreadyExists { uid: 501, .. }));
        assert_eq!(store.get(501).await.unwrap().unwrap().agent, "angie");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn get_refuses_a_symlink_record() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = LocalPrincipalFsStore::new(temp.path().to_path_buf()).unwrap();
        let outside = temp.path().join("outside.toml");
        std::fs::write(&outside, toml::to_string(&principal(501, "angie", "angie")).unwrap())
            .unwrap();
        symlink(&outside, store.target(501)).unwrap();
        assert!(store.get(501).await.is_err());
    }

    #[tokio::test]
    async fn get_refuses_uid_filename_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalPrincipalFsStore::new(temp.path().to_path_buf()).unwrap();
        std::fs::write(
            store.target(501),
            toml::to_string(&principal(502, "angie", "angie")).unwrap(),
        )
        .unwrap();
        assert!(store.get(501).await.is_err());
    }

    #[test]
    fn open_existing_is_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();

        assert!(LocalPrincipalFsStore::open_existing(home.clone()).is_err());
        assert!(!home.join("local-principals").exists());

        LocalPrincipalFsStore::new(home.clone()).unwrap();
        assert!(LocalPrincipalFsStore::open_existing(home).is_ok());
    }
}

fn validate_record(record: &LocalPrincipal) -> Result<(), StoreError> {
    if record.schema_version != 1 && record.schema_version != LOCAL_PRINCIPAL_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedVersion {
            got: record.schema_version,
            expected: LOCAL_PRINCIPAL_SCHEMA_VERSION,
        });
    }
    if record.schema_version == 1
        && record.capabilities != [crate::store::LocalCapability::DriveUpload]
    {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "version-1 local-principal grants must be upload-only",
        )));
    }
    if record.capabilities.is_empty() {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal grant has no capabilities",
        )));
    }
    let mut capabilities = record.capabilities.clone();
    capabilities.sort_unstable();
    capabilities.dedup();
    if capabilities.len() != record.capabilities.len() {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local-principal grant contains duplicate capabilities",
        )));
    }
    if record.platform != "macos" {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported local-principal platform",
        )));
    }
    if record.uid < 501 {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "root and macOS system accounts cannot be granted local agent access",
        )));
    }
    if record.username_at_grant.is_empty()
        || record.username_at_grant.len() > 255
        || record.username_at_grant.bytes().any(|byte| byte == 0 || byte == b'/')
    {
        return Err(StoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid local-principal username",
        )));
    }
    if validate_agent_name(&record.agent).is_err() {
        return Err(StoreError::InvalidAgentName { input: record.agent.clone() });
    }
    Ok(())
}
