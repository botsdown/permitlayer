//! On-disk state-machine marker file for `agentsso rotate-key`.
//!
//! The marker file `<home>/vault/.rotation.in-progress` exists for the
//! window between Phase C (keystore swap) and Phase F (cleanup). Its
//! presence at the start of the next `agentsso rotate-key` (or
//! `agentsso start`) invocation triggers the crash-resume path.
//!
//! # Format
//!
//! UTF-8 JSON, written via the same `tempfile + persist + 0o600 +
//! parent dir fsync` discipline as sealed-credential envelopes:
//!
//! ```json
//! {
//!   "version": 1,
//!   "old_keyid": "1f7c4e9bd2a18063",
//!   "new_keyid": "94be5108a3df02cc",
//!   "timestamp": "2026-04-27T12:34:56Z",
//!   "sealed_count": 3
//! }
//! ```
//!
//! `old_keyid` and `new_keyid` are HMAC-SHA256 fingerprints (16 hex
//! chars) per [`permitlayer_vault::MasterKey::fingerprint`]. They are
//! one-way functions of the master keys — readable, but not
//! invertible.
//!
//! # Why not write the keystore swap into the marker?
//!
//! Because the keystore IS the source of truth. The marker exists to
//! tell a resuming process "the keystore swap completed but the
//! filesystem rename pass and agent rebuild did not"; the verifying
//! check is `MasterKey::fingerprint_bytes(keystore.master_key()) ==
//! marker.new_keyid`. If the fingerprints disagree (extremely rare;
//! would indicate manual keystore tampering), resume refuses with a
//! structured error.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::exit5;

pub(crate) const ROTATION_MARKER_FILENAME: &str = ".rotation.in-progress";

/// Schema version for the marker file. Bumping this is a one-shot
/// migration concern; today it's just `1`.
const MARKER_SCHEMA_VERSION: u8 = 1;

/// Marker file contents. Serializable via serde for atomic write +
/// read on the resume path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RotationMarker {
    /// Schema version. Today always `1`.
    pub version: u8,
    /// HMAC-SHA256 fingerprint of the OLD master key (16 hex chars).
    pub old_keyid: String,
    /// HMAC-SHA256 fingerprint of the NEW master key (16 hex chars).
    pub new_keyid: String,
    /// ISO-8601 timestamp of when the rotation entered Phase B.
    pub timestamp: String,
    /// Number of `<service>.sealed.new` files staged in Phase A.
    /// The resume path uses this to cross-check that all expected
    /// rename operations have been performed.
    pub sealed_count: u32,
}

impl RotationMarker {
    pub(crate) fn new(old_keyid: String, new_keyid: String, sealed_count: u32) -> Self {
        Self {
            version: MARKER_SCHEMA_VERSION,
            old_keyid,
            new_keyid,
            timestamp: now_iso8601(),
            sealed_count,
        }
    }

    /// Serialize to canonical JSON for atomic write. Pretty-printed
    /// with a trailing newline so an operator inspecting the file via
    /// `cat` sees a readable record.
    pub(crate) fn to_json(&self) -> String {
        // serde_json::to_string_pretty cannot fail for owned
        // String/u8/u32 fields. The error arm is unreachable; map it
        // to a degraded `{}` rather than panicking — the only field
        // this feeds is the on-disk marker, and a degraded write
        // would still be re-tried on the next invocation. (Reached
        // only via clippy::expect_used compliance, NOT real runtime.)
        let mut s = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_owned());
        s.push('\n');
        s
    }

    /// Write the marker atomically: tempfile → fsync → rename → fsync
    /// parent. Mirrors the `credential_fs` + `agent_fs` patterns.
    pub(crate) fn write_atomic(&self, vault_dir: &Path) -> Result<(), anyhow::Error> {
        use std::io::Write as _;

        std::fs::create_dir_all(vault_dir)?;
        let target = vault_dir.join(ROTATION_MARKER_FILENAME);
        let pid = std::process::id();
        let tmp = vault_dir.join(format!(".rotation.in-progress.tmp.{pid}"));

        let result = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let perms = std::fs::Permissions::from_mode(0o600);
                f.set_permissions(perms)?;
            }
            f.write_all(self.to_json().as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &target)?;
            // Best-effort parent-dir fsync (Story 7.3 P60 precedent).
            if let Ok(dir) = std::fs::File::open(vault_dir) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(anyhow::Error::from)
    }

    /// Read + parse the marker file at the canonical location. Returns
    /// `Err(exit5)` on parse failure (best treated as exit-code 5
    /// since a corrupt marker means rotation state is unrecoverable
    /// without manual intervention).
    pub(crate) fn read(vault_dir: &Path) -> Result<Self, anyhow::Error> {
        let path = vault_dir.join(ROTATION_MARKER_FILENAME);
        let bytes = std::fs::read(&path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "failed to read rotation marker");
            exit5()
        })?;
        let marker: RotationMarker = serde_json::from_slice(&bytes).map_err(|e| {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "rotation marker is unparseable; manual intervention required"
            );
            exit5()
        })?;
        if marker.version != MARKER_SCHEMA_VERSION {
            tracing::error!(
                path = %path.display(),
                got = marker.version,
                expected = MARKER_SCHEMA_VERSION,
                "rotation marker schema version mismatch"
            );
            return Err(exit5());
        }
        Ok(marker)
    }

    /// Path to the canonical marker location for a given vault dir.
    pub(crate) fn path(vault_dir: &Path) -> PathBuf {
        vault_dir.join(ROTATION_MARKER_FILENAME)
    }
}

/// Best-effort ISO-8601 UTC timestamp. Uses `chrono` (already a
/// workspace dep — used by the audit log) so the format matches what
/// audit consumers already parse.
fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn marker_round_trips_through_json() {
        let m = RotationMarker::new("aaaa1111".into(), "bbbb2222".into(), 5);
        let json = m.to_json();
        let parsed: RotationMarker = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, MARKER_SCHEMA_VERSION);
        assert_eq!(parsed.old_keyid, "aaaa1111");
        assert_eq!(parsed.new_keyid, "bbbb2222");
        assert_eq!(parsed.sealed_count, 5);
        assert!(parsed.timestamp.contains('T'));
    }

    #[test]
    fn write_atomic_creates_file_with_canonical_name() {
        let tmp = TempDir::new().unwrap();
        let m = RotationMarker::new("oldoldkeyhex0001".into(), "newnewkeyhex0002".into(), 2);
        m.write_atomic(tmp.path()).unwrap();
        let written = tmp.path().join(ROTATION_MARKER_FILENAME);
        assert!(written.exists());
        let read_back = RotationMarker::read(tmp.path()).unwrap();
        assert_eq!(read_back.old_keyid, "oldoldkeyhex0001");
        assert_eq!(read_back.sealed_count, 2);
    }

    #[test]
    fn read_returns_exit5_error_on_corrupt_marker() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(ROTATION_MARKER_FILENAME), b"{not valid json").unwrap();
        let err = RotationMarker::read(tmp.path()).unwrap_err();
        // Downcast to the typed RotateKeyExitCode5 marker.
        assert!(err.chain().any(|c| c.is::<super::super::RotateKeyExitCode5>()));
    }

    #[test]
    fn read_returns_exit5_on_schema_version_mismatch() {
        let tmp = TempDir::new().unwrap();
        let json = r#"{
            "version": 99,
            "old_keyid": "a",
            "new_keyid": "b",
            "timestamp": "2026-04-27T00:00:00Z",
            "sealed_count": 0
        }"#;
        std::fs::write(tmp.path().join(ROTATION_MARKER_FILENAME), json).unwrap();
        let err = RotationMarker::read(tmp.path()).unwrap_err();
        assert!(err.chain().any(|c| c.is::<super::super::RotateKeyExitCode5>()));
    }

    #[cfg(unix)]
    #[test]
    fn marker_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = TempDir::new().unwrap();
        let m = RotationMarker::new("a".into(), "b".into(), 0);
        m.write_atomic(tmp.path()).unwrap();
        let perms =
            std::fs::metadata(tmp.path().join(ROTATION_MARKER_FILENAME)).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
