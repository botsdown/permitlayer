//! Atomic swap + rollback state machine for `agentsso update --apply`.
//!
//! The contract:
//!
//! - `<install_dir>/agentsso.new` is staged from the verified
//!   extracted binary.
//! - `<install_dir>/agentsso` is renamed to `<install_dir>/agentsso.old`.
//! - `<install_dir>/agentsso.new` is renamed to `<install_dir>/agentsso`.
//!
//! Both renames happen on the same filesystem (we stage in the
//! install directory specifically to guarantee `rename(2)`'s
//! atomic-on-same-FS semantics). On Windows the running binary is
//! locked, so the daemon MUST be stopped before the second rename.
//!
//! Rollback inverse: rename `<install_dir>/agentsso.old` back to
//! `<install_dir>/agentsso`, then re-spawn the daemon from the old
//! binary path.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

/// The three filenames that anchor a swap. Constructing a fresh
/// instance per swap (no global state) keeps tests trivial.
#[derive(Debug, Clone)]
pub(crate) struct SwapPaths {
    /// The current binary path. e.g. `/usr/local/bin/agentsso`.
    pub(crate) current: PathBuf,
    /// The staged-new-binary path. e.g.
    /// `/usr/local/bin/agentsso.new`.
    pub(crate) new: PathBuf,
    /// The pre-swap-backup path. e.g.
    /// `/usr/local/bin/agentsso.old`.
    pub(crate) old: PathBuf,
}

impl SwapPaths {
    pub(crate) fn from_current(current: PathBuf) -> Self {
        let new = path_with_extension(&current, "new");
        let old = path_with_extension(&current, "old");
        Self { current, new, old }
    }
}

/// Append a tag (`new` / `old`) to a path while preserving the
/// existing extension.
///
/// `agentsso` → `agentsso.new`
/// `agentsso.exe` → `agentsso.exe.new`
fn path_with_extension(path: &Path, tag: &str) -> PathBuf {
    let mut out = path.as_os_str().to_owned();
    out.push(".");
    out.push(tag);
    PathBuf::from(out)
}

/// Stage `verified_source` into `paths.new`, copying bytes and
/// re-applying the executable bit on POSIX.
///
/// On macOS/Linux: `set_permissions(0o755)` after the copy.
/// On Windows: no chmod step (executability comes from the file
/// extension).
pub(crate) fn stage_new_binary(verified_source: &Path, paths: &SwapPaths) -> Result<()> {
    if paths.new.exists() {
        // A leftover `<binary>.new` from a previous failed run is
        // unsafe to reuse — we don't know if it's signature-verified.
        // Remove it explicitly. Per Story 7.4 P38: Windows file-lock
        // may need a brief retry on `ERROR_SHARING_VIOLATION`.
        remove_with_retry(&paths.new).with_context(|| {
            format!("could not remove leftover staged binary at {}", paths.new.display())
        })?;
    }
    std::fs::copy(verified_source, &paths.new).with_context(|| {
        format!("stage {} → {} failed", verified_source.display(), paths.new.display())
    })?;

    // Re-apply the executable bit on POSIX. Windows has no chmod step
    // — executability is bound to the file extension on NTFS.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(&paths.new)
            .with_context(|| format!("stat {} for chmod failed", paths.new.display()))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&paths.new, perms)
            .with_context(|| format!("chmod 0755 {} failed", paths.new.display()))?;
    }
    Ok(())
}

/// Perform the two renames atomically (in the same parent directory).
///
/// On step-A success + step-B failure, rolls back step A immediately
/// so the caller sees the original binary still in place.
pub(crate) fn atomic_swap(paths: &SwapPaths) -> Result<()> {
    // **Review patch P5 (F6 — Edge):** if `<binary>.old` already
    // exists from a previous failed run, removing it BEFORE step A
    // ensures step A's rename doesn't silently overwrite the
    // previous-known-good binary. Without this, a previous-run
    // leftover would be clobbered, and a future rollback would
    // restore the *current* version (which is what we just renamed)
    // rather than the actual old binary the user wanted preserved.
    //
    // Failure to remove is a hard error: we'd rather refuse the
    // swap than silently corrupt the rollback artifact.
    if paths.old.exists() {
        remove_with_retry(&paths.old).with_context(|| {
            format!(
                "could not remove leftover {} (likely from a previous failed update); \
                 refusing to swap to avoid clobbering the rollback artifact",
                paths.old.display()
            )
        })?;
    }

    // Step A: current → old.
    rename_with_retry(&paths.current, &paths.old).with_context(|| {
        format!("rename {} → {} failed (step A)", paths.current.display(), paths.old.display())
    })?;

    // Step B: new → current.
    if let Err(e) = rename_with_retry(&paths.new, &paths.current) {
        // Inverse step A. Best-effort — if THIS fails too, surface
        // the compound failure so the operator sees both errors.
        let inverse = rename_with_retry(&paths.old, &paths.current).with_context(|| {
            format!(
                "rolling back step A: rename {} → {} failed",
                paths.old.display(),
                paths.current.display()
            )
        });
        return Err(anyhow!(
            "rename {} → {} failed (step B): {e}{}",
            paths.new.display(),
            paths.current.display(),
            match inverse {
                Ok(()) => " — step A rolled back successfully".to_string(),
                Err(e2) => format!(" — AND step A rollback ALSO failed: {e2}"),
            }
        ));
    }
    Ok(())
}

/// Rollback inverse: rename `paths.old` back to `paths.current`.
///
/// Idempotent — succeeds quietly if `paths.old` doesn't exist.
pub(crate) fn rollback_rename(paths: &SwapPaths) -> Result<()> {
    if !paths.old.exists() {
        // Nothing to roll back. Either we never reached step A, OR
        // a previous rollback already restored. Both are fine.
        return Ok(());
    }
    rename_with_retry(&paths.old, &paths.current).with_context(|| {
        format!("rollback rename {} → {} failed", paths.old.display(), paths.current.display())
    })
}

/// Cleanup helper — remove `paths.old` after a confirmed-successful
/// update. Logged-and-ignored if it fails (the update succeeded; a
/// stale `.old` file is operator clutter at worst).
pub(crate) fn cleanup_old_binary(paths: &SwapPaths) {
    if paths.old.exists()
        && let Err(e) = remove_with_retry(&paths.old)
    {
        tracing::warn!(
            target: "update",
            path = %paths.old.display(),
            error = %e,
            "could not remove .old binary after successful update — operator can rm manually"
        );
    }
}

/// `std::fs::rename` with up-to-3 retries on Windows file-lock /
/// sharing-violation errors. Linear backoff: 500/1000/2000ms.
/// Mirrors Story 7.4 P38's pattern for `remove_file`.
///
/// On POSIX rename never blocks on locks — the loop runs exactly
/// once.
fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let backoffs = [500u64, 1000, 2000];
    for (i, backoff_ms) in backoffs.iter().enumerate() {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if is_locked_error(&e) && i + 1 < backoffs.len() => {
                std::thread::sleep(std::time::Duration::from_millis(*backoff_ms));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `std::fs::remove_file` with the same retry scheme.
fn remove_with_retry(path: &Path) -> std::io::Result<()> {
    let backoffs = [500u64, 1000, 2000];
    for (i, backoff_ms) in backoffs.iter().enumerate() {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if is_locked_error(&e) && i + 1 < backoffs.len() => {
                std::thread::sleep(std::time::Duration::from_millis(*backoff_ms));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Windows ERROR_SHARING_VIOLATION (32) / ERROR_LOCK_VIOLATION (33).
/// On POSIX always `false`. Same helper Story 7.4 uses in
/// `cli/uninstall/mod.rs::is_locked_error`.
fn is_locked_error(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(32) | Some(33))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn path_with_extension_appends_dot_tag_to_no_ext() {
        let p = path_with_extension(Path::new("/usr/local/bin/agentsso"), "new");
        assert_eq!(p, PathBuf::from("/usr/local/bin/agentsso.new"));
    }

    #[test]
    fn path_with_extension_appends_to_existing_ext() {
        let p = path_with_extension(Path::new("C:/Programs/agentsso.exe"), "old");
        assert_eq!(p, PathBuf::from("C:/Programs/agentsso.exe.old"));
    }

    #[test]
    fn swap_paths_constructs_three_distinct_paths() {
        let paths = SwapPaths::from_current(PathBuf::from("/u/l/b/agentsso"));
        assert_eq!(paths.current, PathBuf::from("/u/l/b/agentsso"));
        assert_eq!(paths.new, PathBuf::from("/u/l/b/agentsso.new"));
        assert_eq!(paths.old, PathBuf::from("/u/l/b/agentsso.old"));
    }

    #[test]
    fn stage_then_atomic_swap_then_rollback_produces_original_state() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"OLD").unwrap();
        let new_source = tmp.path().join("agentsso.new-source");
        std::fs::write(&new_source, b"NEW").unwrap();

        let paths = SwapPaths::from_current(current.clone());

        // Stage.
        stage_new_binary(&new_source, &paths).unwrap();
        assert!(paths.new.exists());

        // Swap.
        atomic_swap(&paths).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&paths.old).unwrap(), b"OLD");
        assert!(!paths.new.exists());

        // Rollback.
        rollback_rename(&paths).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"OLD");
        assert!(!paths.old.exists());
    }

    #[test]
    fn rollback_rename_is_idempotent_when_old_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"OLD").unwrap();
        let paths = SwapPaths::from_current(current);
        // No .old file present — rollback is a no-op.
        rollback_rename(&paths).unwrap();
    }

    /// P5 (review F6 — Edge): an already-existing `.old` from a
    /// previous failed run must be removed before step A, so step A
    /// doesn't clobber the previous-known-good binary.
    #[test]
    fn atomic_swap_removes_leftover_old_before_step_a() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"CURRENT").unwrap();
        let paths = SwapPaths::from_current(current);
        // Seed a leftover .old (simulating a previous failed run).
        std::fs::write(&paths.old, b"PREVIOUS_KNOWN_GOOD_BUT_NOW_STALE").unwrap();
        // Stage a fresh .new.
        std::fs::write(&paths.new, b"NEW").unwrap();

        atomic_swap(&paths).unwrap();

        // Post-swap: current is NEW, old is the pre-swap CURRENT
        // (NOT the stale "PREVIOUS_KNOWN_GOOD_BUT_NOW_STALE").
        assert_eq!(std::fs::read(&paths.current).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&paths.old).unwrap(), b"CURRENT");
    }

    #[test]
    fn cleanup_old_binary_removes_old_file() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"NEW").unwrap();
        let paths = SwapPaths::from_current(current);
        std::fs::write(&paths.old, b"OLD").unwrap();
        cleanup_old_binary(&paths);
        assert!(!paths.old.exists());
    }

    #[test]
    fn cleanup_old_binary_is_quiet_when_old_already_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"NEW").unwrap();
        let paths = SwapPaths::from_current(current);
        // Should not panic / emit anything operator-visible.
        cleanup_old_binary(&paths);
    }

    #[cfg(unix)]
    #[test]
    fn stage_new_binary_sets_executable_bit_on_posix() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"OLD").unwrap();
        let new_source = tmp.path().join("agentsso.new-source");
        std::fs::write(&new_source, b"NEW").unwrap();
        // Strip executable bits from the source.
        std::fs::set_permissions(&new_source, std::fs::Permissions::from_mode(0o600)).unwrap();

        let paths = SwapPaths::from_current(current);
        stage_new_binary(&new_source, &paths).unwrap();
        let mode = std::fs::metadata(&paths.new).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn stage_new_binary_overwrites_leftover_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("agentsso");
        std::fs::write(&current, b"CURRENT").unwrap();
        let paths = SwapPaths::from_current(current);
        // Pretend a previous failed run left a .new behind.
        std::fs::write(&paths.new, b"STALE").unwrap();

        let new_source = tmp.path().join("agentsso.new-source");
        std::fs::write(&new_source, b"FRESH").unwrap();
        stage_new_binary(&new_source, &paths).unwrap();
        assert_eq!(std::fs::read(&paths.new).unwrap(), b"FRESH");
    }
}
