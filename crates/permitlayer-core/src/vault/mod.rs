//! Vault-level coordination primitives (Story 7.6a).
//!
//! Currently exposes [`lock::VaultLock`] — an advisory `flock`/`LockFileEx`
//! guard that serializes every vault writer (the daemon and every CLI
//! subcommand). Future stories may add additional primitives (read-locks,
//! metric counters) here; the module is intentionally narrow at MVP.

pub mod lock;
