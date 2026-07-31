//! Windows platform integration for PermitLayer.
//!
//! This crate is the isolation seam for the small amount of Win32 FFI that
//! PermitLayer needs. Callers consume safe Rust APIs and retain their
//! `#![forbid(unsafe_code)]` boundary.

#![cfg(windows)]

use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

/// Atomically replace `destination` with `replacement` on the same volume.
///
/// `destination` must already exist. On success, Windows removes the
/// replacement path and the destination names the replacement file contents.
/// The operation requests write-through durability from `ReplaceFileW`.
pub fn replace_file(replacement: &Path, destination: &Path) -> io::Result<()> {
    let replacement = wide_path(replacement)?;
    let destination = wide_path(destination)?;

    // SAFETY: `wide_path` returns owned, NUL-terminated UTF-16 buffers that
    // remain alive for the call. The optional backup name and reserved
    // pointers are null as required by ReplaceFileW. Win32 does not retain
    // either path pointer after the function returns.
    let replaced = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            windows_sys::Win32::Storage::FileSystem::REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if replaced == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an embedded NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn atomically_replaces_existing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("destination.bin");
        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&destination, b"old").expect("write destination");
        std::fs::write(&replacement, b"new").expect("write replacement");

        replace_file(&replacement, &destination).expect("replace file");

        assert_eq!(std::fs::read(&destination).expect("read destination"), b"new");
        assert!(!replacement.exists());
    }

    #[test]
    fn refuses_missing_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("missing.bin");
        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&replacement, b"new").expect("write replacement");

        assert!(replace_file(&replacement, &destination).is_err());
        assert_eq!(std::fs::read(&replacement).expect("replacement retained"), b"new");
    }
}
