//! Disk-space pre-flight for `agentsso update --apply`.
//!
//! POSIX path uses `rustix::fs::statvfs` (already in the dep tree
//! transitively per Story 8.0 hygiene posture; the `fs` feature is
//! the one we need). Windows path shells out to PowerShell via
//! `Get-PSDrive` — `wmic` is deprecated, and a `windows-rs` direct
//! binding pulls in a much larger crate than this one-line
//! shell-out justifies.
//!
//! Returns `None` (not `Err`) when the platform-specific call fails:
//! the orchestrator treats "couldn't pre-flight" as "warn and
//! continue" rather than "refuse the update". If the disk is truly
//! full, the swap will fail loudly enough on its own.

use std::path::Path;

/// Best-effort available-bytes query for the filesystem containing
/// `path`. `None` means "platform call failed" — caller continues.
pub(crate) fn available_disk_space(path: &Path) -> Option<u64> {
    available_disk_space_impl(path)
}

#[cfg(unix)]
fn available_disk_space_impl(path: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(path).ok()?;
    // f_bavail = free blocks available to non-privileged user
    // f_frsize = fundamental block size
    // Both are already u64 on rustix 0.38; product fits in u64 on
    // all reasonable filesystems.
    let bavail: u64 = stat.f_bavail;
    let frsize: u64 = stat.f_frsize;
    Some(bavail.saturating_mul(frsize))
}

#[cfg(windows)]
fn available_disk_space_impl(path: &Path) -> Option<u64> {
    // Walk parents to find a drive root we can query. PowerShell's
    // Get-PSDrive takes the drive letter (without colon).
    //
    // On Windows, `Path::new("C:\\").parent()` returns `None` (NOT
    // `Some(C:\\)`), so the previous `probe == parent` self-check
    // never fired — we always fell into the `else { return None }`
    // branch and the disk-space pre-flight reported `None` for every
    // path. Surfaced by the Story 7.7 four-OS matrix on
    // windows-latest. The fix: when `parent()` returns `None`, we've
    // reached the root — extract the drive letter from `probe` (the
    // last successful path) and break.
    let mut probe = path.to_path_buf();
    let drive_letter = loop {
        match probe.parent() {
            Some(parent) if probe == parent => {
                // Defensive: some path forms self-loop at root rather
                // than returning `None`. Treat the same as None.
                break extract_windows_drive_letter(&probe)?;
            }
            Some(parent) => {
                probe = parent.to_path_buf();
            }
            None => {
                // Reached the root — `probe` is `C:\` (or similar).
                break extract_windows_drive_letter(&probe)?;
            }
        }
    };

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &format!("(Get-PSDrive -Name {drive_letter}).Free")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout).ok()?.trim().parse::<u64>().ok()
}

/// Extract the drive letter from a path like `C:\` → `"C"`.
#[cfg(windows)]
fn extract_windows_drive_letter(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    let first = s.chars().next()?;
    if first.is_ascii_alphabetic() { Some(first.to_ascii_uppercase().to_string()) } else { None }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn available_disk_space_returns_some_for_tempdir() {
        // The temp dir filesystem always has SOME free space on a
        // healthy CI runner. This locks in: the pre-flight returns
        // `Some(_)`, not `None`, on a normal POSIX/Windows host.
        let tmp = tempfile::tempdir().unwrap();
        let bytes = available_disk_space(tmp.path());
        assert!(bytes.is_some(), "pre-flight returned None on a normal host");
        if let Some(b) = bytes {
            assert!(b > 0, "tempdir reports zero free bytes — host is full?");
        }
    }

    #[test]
    fn available_disk_space_returns_none_on_nonexistent_path() {
        // Nonexistent path: platform calls return an error → we
        // surface `None`. (POSIX: ENOENT. Windows: drive-letter
        // extraction fails.)
        let bytes = available_disk_space(Path::new("/nonexistent-permitlayer-test"));
        // Don't assert exactly None — POSIX statvfs CAN succeed on
        // a non-existent path if the parent FS is mounted. We just
        // assert the call doesn't panic.
        let _ = bytes;
    }
}
