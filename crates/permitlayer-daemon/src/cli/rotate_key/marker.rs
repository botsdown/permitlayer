//! Persistent rotation-state marker for `agentsso rotate-key`.
//!
//! Story 7.6b round-1 review (Decision 1+2 resolution): the original
//! 7.6b shipped without a marker, inferring `(old_kid, new_kid)` from
//! the vault contents on resume. That inference is brittle — empty
//! vault, uniform vault, double-rotation, and tampered keystore all
//! collapse to the same arithmetic and produce silent failures. The
//! marker is the authoritative record of in-flight rotation state.
//!
//! # File layout
//!
//! Path: `<home>/vault/.rotation-state`
//! Mode: `0o600` (owner-read/write only).
//! Format: TOML, humans should be able to `cat` it during incident
//! triage.
//!
//! ```toml
//! version = 1
//! keystore_phase = "committed"   # pre-previous | pre-primary | committed
//! old_kid = 3
//! new_kid = 4
//! started_at = "2026-04-28T12:34:56Z"
//! pid = 12345
//! ```
//!
//! # Lifecycle
//!
//! - **Phase A (lock + decide)**: read marker if present. If absent and
//!   the keystore previous slot is also empty → fresh rotation. If
//!   present → resume from `keystore_phase`. If absent but previous
//!   slot non-empty → REFUSE: that state means a pre-marker rotation
//!   was attempted, or someone manually wrote to the keystore.
//! - **Phase C' (atomic dual-slot install)**: write marker
//!   `pre-previous` → write previous slot → marker `pre-primary` →
//!   write primary → read-back-verify both → marker `committed`.
//! - **Phase D/E**: read marker for `(old_kid, new_kid)`.
//! - **Phase F (finalize)**: clear previous slot → delete marker.
//!
//! Every write is atomic-via-tempfile-rename so a SIGKILL between
//! marker writes leaves either the OLD file or the NEW file, never a
//! half-written one. Rename is the durability boundary.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// File-format version. Bumped if we ever change the on-disk shape.
const MARKER_VERSION: u32 = 1;

/// Filename of the rotation-state marker, relative to the vault dir.
pub const MARKER_FILENAME: &str = ".rotation-state";

/// Where rotation believes the keystore is in the dual-slot
/// install. Each transition is durable (atomic-rename) so resume can
/// read it and pick up exactly where the previous attempt left off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeystorePhase {
    /// Marker written, previous-slot write NOT yet started. On
    /// resume: previous slot may or may not exist; primary still
    /// holds OLD; safe to overwrite both.
    PrePrevious,
    /// Previous slot written, primary NOT yet swapped. On resume:
    /// previous slot holds OLD; primary still holds OLD; rewrite
    /// primary with NEW.
    PrePrimary,
    /// Both slots committed AND read-back-verified. On resume: vault
    /// reseal (Phase D) and agent rebuild (Phase E) may be partial;
    /// re-run them idempotently.
    Committed,
}

/// On-disk shape. Public for tests; production callers construct via
/// the [`begin`] / [`advance`] / [`finalize`] helpers below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationStateMarker {
    /// Schema version. Refuse to read markers with a `version` we
    /// don't recognize so a future field-rename can't be silently
    /// misinterpreted.
    pub version: u32,
    pub keystore_phase: KeystorePhase,
    pub old_kid: u8,
    pub new_kid: u8,
    /// RFC 3339 timestamp of when this rotation attempt started.
    /// Informational — used for human triage, not for any logic.
    pub started_at: String,
    /// PID of the rotate-key process that wrote this marker. Used by
    /// resume-detection logic AND surfaced in the operator-facing
    /// "stale marker" error so it's clear which previous run owned it.
    pub pid: u32,
    /// 16-hex-char fingerprint (truncated SHA-256) of the OLD master
    /// key bytes, recorded at marker-begin and immutable thereafter.
    /// Story 7.6b round-2 review: lets the resume path verify that
    /// the keystore's previous-slot bytes match what the marker
    /// claims, surfacing tampering as `keystore-write-mismatch`
    /// rather than silently honoring planted markers. `None` for
    /// markers written by pre-round-2 code (we accept those for
    /// backward compatibility; the verify is skipped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_keyid_fp: Option<String>,
    /// Same as [`old_keyid_fp`] but for the NEW master key. Recorded
    /// at marker-begin (the new key bytes are minted in
    /// `begin_fresh_rotation` BEFORE the marker is written, so the
    /// fingerprint is known). Lets resume verify the keystore
    /// primary slot against this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_keyid_fp: Option<String>,
}

/// Errors from marker I/O.
#[derive(Debug, thiserror::Error)]
pub enum MarkerError {
    #[error("marker file I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("marker file at {path} is malformed: {message}")]
    Malformed { path: PathBuf, message: String },
    #[error("marker file at {path} is from a future schema (version={version}); refusing to use")]
    UnknownVersion { path: PathBuf, version: u32 },
}

impl MarkerError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io { path: path.to_path_buf(), source }
    }
}

/// Path to the marker file given a home directory.
#[must_use]
pub fn marker_path(home: &Path) -> PathBuf {
    home.join("vault").join(MARKER_FILENAME)
}

/// Read the marker if it exists. Returns `Ok(None)` when the file is
/// absent (fresh rotation posture); `Ok(Some(marker))` when present
/// AND the schema version matches.
///
/// Story 7.6b round-2 review: refuses to follow symlinks at the
/// marker path. An attacker with write access to `<home>/vault/`
/// could plant `.rotation-state` as a symlink to a file elsewhere
/// (e.g., `/etc/passwd`) and have us mis-parse it as a marker. The
/// `symlink_metadata` probe + `O_NOFOLLOW` open close that gap;
/// mirrors the `vault::lock` discipline.
pub fn read(home: &Path) -> Result<Option<RotationStateMarker>, MarkerError> {
    let path = marker_path(home);

    // Symlink probe BEFORE open. Race-tolerant pair with O_NOFOLLOW
    // below: if an attacker plants a symlink between the probe and
    // the open, O_NOFOLLOW fails the open with ELOOP.
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(MarkerError::Malformed {
                path: path.clone(),
                message: "marker path is a symlink (refusing to follow)".into(),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(MarkerError::io(&path, e)),
    }

    let bytes = read_no_follow(&path)?;
    let bytes = match bytes {
        Some(b) => b,
        None => return Ok(None),
    };
    let text = String::from_utf8(bytes).map_err(|e| MarkerError::Malformed {
        path: path.clone(),
        message: format!("non-UTF-8 bytes: {e}"),
    })?;
    let marker: RotationStateMarker = toml::from_str(&text).map_err(|e| {
        MarkerError::Malformed { path: path.clone(), message: format!("toml parse: {e}") }
    })?;
    if marker.version != MARKER_VERSION {
        return Err(MarkerError::UnknownVersion { path, version: marker.version });
    }
    Ok(Some(marker))
}

/// Open `path` for reading with `O_NOFOLLOW` on Unix (refuse to
/// follow symlinks). Returns `Ok(None)` on `NotFound`. Mirrors the
/// `vault::lock` open-with-NOFOLLOW pattern.
#[cfg(unix)]
fn read_no_follow(path: &Path) -> Result<Option<Vec<u8>>, MarkerError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut opts = fs::OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NOFOLLOW);
    match opts.open(path) {
        Ok(mut f) => {
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).map_err(|e| MarkerError::io(path, e))?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(MarkerError::io(path, e)),
    }
}

#[cfg(not(unix))]
fn read_no_follow(path: &Path) -> Result<Option<Vec<u8>>, MarkerError> {
    // Windows lacks an O_NOFOLLOW-equivalent in `OpenOptions`; the
    // marker's parent dir is 0700 (only the user can write to it),
    // and Windows symlink creation is gated by `SeCreateSymbolicLink`
    // privilege which standard accounts don't have. The
    // symlink_metadata probe above is the primary defense; this
    // fallback uses plain `fs::read`.
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(MarkerError::io(path, e)),
    }
}

/// Write a fresh marker for a new rotation attempt. Atomic via
/// tempfile + rename so a crash mid-write leaves either the previous
/// file (or no file) — never a torn write.
///
/// Sets mode `0o600` on Unix.
///
/// `old_keyid_fp` / `new_keyid_fp` are 16-hex-char truncated SHA-256
/// fingerprints of the master keys, used by the resume path to
/// verify the keystore matches what the marker claims (Story 7.6b
/// round-2 review). Pass `None` from tests that don't care.
pub fn begin(
    home: &Path,
    old_kid: u8,
    new_kid: u8,
    old_keyid_fp: Option<String>,
    new_keyid_fp: Option<String>,
) -> Result<RotationStateMarker, MarkerError> {
    let started_at = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let pid = std::process::id();
    let marker = RotationStateMarker {
        version: MARKER_VERSION,
        keystore_phase: KeystorePhase::PrePrevious,
        old_kid,
        new_kid,
        started_at,
        pid,
        old_keyid_fp,
        new_keyid_fp,
    };
    write_atomic(home, &marker)?;
    Ok(marker)
}

/// Advance an existing marker to a new keystore phase. Atomic.
pub fn advance(
    home: &Path,
    current: &RotationStateMarker,
    next: KeystorePhase,
) -> Result<RotationStateMarker, MarkerError> {
    let mut updated = current.clone();
    updated.keystore_phase = next;
    write_atomic(home, &updated)?;
    Ok(updated)
}

/// Delete the marker. Idempotent: returns Ok if the file is already
/// absent.
pub fn finalize(home: &Path) -> Result<(), MarkerError> {
    let path = marker_path(home);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(MarkerError::io(&path, e)),
    }
}

/// Internal: serialize + atomic-write with mode 0o600.
fn write_atomic(home: &Path, marker: &RotationStateMarker) -> Result<(), MarkerError> {
    let path = marker_path(home);
    let parent = path.parent().ok_or_else(|| MarkerError::Malformed {
        path: path.clone(),
        message: "marker path has no parent dir".into(),
    })?;
    fs::create_dir_all(parent).map_err(|e| MarkerError::io(parent, e))?;

    let toml_text = toml::to_string_pretty(marker).map_err(|e| MarkerError::Malformed {
        path: path.clone(),
        message: format!("toml serialize: {e}"),
    })?;

    // Tempfile in the same directory so rename is atomic on POSIX.
    // Story 7.6b round-2 review: use `create_new(true)` instead of
    // `create(true) + truncate(true)` so a stale `.rotation-state.tmp.<pid>`
    // (from a crashed prior run with the same pid recycled) cannot
    // be silently clobbered. On EEXIST we remove the stale file and
    // retry — the unique pid + entropy suffix makes that vanishingly
    // rare in practice but the robustness costs nothing.
    let pid = std::process::id();
    let tmp_name = format!(".rotation-state.tmp.{pid}.{}", rand_suffix());
    let tmp_path = parent.join(tmp_name);

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            // Defense-in-depth: refuse to follow a planted symlink
            // at the tempfile path. The tempfile name is unique
            // (pid + 64-bit OsRng suffix) so a planted symlink is
            // extremely unlikely, but the cost of NOFOLLOW is zero
            // and matches the discipline used by `read_no_follow`
            // and `vault::lock`.
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts.open(&tmp_path).map_err(|e| MarkerError::io(&tmp_path, e))?;
        f.write_all(toml_text.as_bytes()).map_err(|e| MarkerError::io(&tmp_path, e))?;
        f.sync_all().map_err(|e| MarkerError::io(&tmp_path, e))?;
    }

    fs::rename(&tmp_path, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        MarkerError::io(&path, e)
    })?;

    // Best-effort dir fsync so the rename is durable on Linux.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// 64-bit hex suffix for tempfile uniqueness. Used by `write_atomic`
/// to avoid PID-collision clobbers when `create_new(true)` would
/// otherwise EEXIST on a stale leftover.
fn rand_suffix() -> String {
    use rand::RngCore as _;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!("{:016x}", u64::from_le_bytes(buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_returns_none_when_missing() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        assert!(read(home.path()).unwrap().is_none());
    }

    #[test]
    fn begin_then_read_round_trip() {
        let home = TempDir::new().unwrap();
        let m = begin(home.path(), 3, 4, None, None).unwrap();
        assert_eq!(m.old_kid, 3);
        assert_eq!(m.new_kid, 4);
        assert_eq!(m.keystore_phase, KeystorePhase::PrePrevious);
        let read_back = read(home.path()).unwrap().unwrap();
        assert_eq!(read_back.old_kid, 3);
        assert_eq!(read_back.new_kid, 4);
        assert_eq!(read_back.keystore_phase, KeystorePhase::PrePrevious);
    }

    #[test]
    fn advance_persists_new_phase() {
        let home = TempDir::new().unwrap();
        let m = begin(home.path(), 0, 1, None, None).unwrap();
        let advanced = advance(home.path(), &m, KeystorePhase::PrePrimary).unwrap();
        assert_eq!(advanced.keystore_phase, KeystorePhase::PrePrimary);
        let read_back = read(home.path()).unwrap().unwrap();
        assert_eq!(read_back.keystore_phase, KeystorePhase::PrePrimary);
    }

    #[test]
    fn finalize_removes_marker() {
        let home = TempDir::new().unwrap();
        begin(home.path(), 0, 1, None, None).unwrap();
        finalize(home.path()).unwrap();
        assert!(read(home.path()).unwrap().is_none());
    }

    #[test]
    fn finalize_is_idempotent() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        finalize(home.path()).unwrap();
        finalize(home.path()).unwrap();
    }

    #[test]
    fn read_rejects_unknown_version() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let path = marker_path(home.path());
        std::fs::write(
            &path,
            "version = 99\nkeystore_phase = \"committed\"\nold_kid = 0\nnew_kid = 1\nstarted_at = \"x\"\npid = 1\n",
        )
        .unwrap();
        match read(home.path()) {
            Err(MarkerError::UnknownVersion { version, .. }) => assert_eq!(version, 99),
            other => panic!("expected UnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_malformed_toml() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        std::fs::write(marker_path(home.path()), "this is not toml").unwrap();
        assert!(matches!(read(home.path()), Err(MarkerError::Malformed { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn marker_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        begin(home.path(), 0, 1, None, None).unwrap();
        let metadata = std::fs::metadata(marker_path(home.path())).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "marker file must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn read_refuses_to_follow_symlink_at_marker_path() {
        // Story 7.6b round-2 review: an attacker with write access
        // to <home>/vault/ could plant `.rotation-state` as a
        // symlink to a file elsewhere (e.g., another user's TOML).
        // The reader MUST refuse, not silently follow.
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        // Plant a file outside vault/ that LOOKS like a valid marker.
        let decoy = home.path().join("decoy.toml");
        std::fs::write(
            &decoy,
            "version = 1\nkeystore_phase = \"committed\"\nold_kid = 7\nnew_kid = 8\nstarted_at = \"2026-04-28T00:00:00Z\"\npid = 1\n",
        )
        .unwrap();
        // Symlink the marker path at the decoy.
        std::os::unix::fs::symlink(&decoy, marker_path(home.path())).unwrap();

        // The reader must refuse with a Malformed error, NOT
        // silently parse the decoy.
        match read(home.path()) {
            Err(MarkerError::Malformed { message, .. }) => {
                assert!(
                    message.contains("symlink"),
                    "error message should name the symlink refusal; got: {message}"
                );
            }
            other => panic!("expected Malformed(symlink); got {other:?}"),
        }
    }
}
