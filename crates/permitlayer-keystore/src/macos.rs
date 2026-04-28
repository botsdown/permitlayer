//! macOS Keychain Services adapter.
//!
//! Persists a single 32-byte master-key entry at
//! (`MASTER_KEY_SERVICE`, `MASTER_KEY_ACCOUNT`) via the `keyring` crate.
//! All FFI calls are dispatched through `tokio::task::spawn_blocking`
//! (AC #3) so a slow keychain operation (the OS can prompt the user,
//! talk over XPC, etc.) can never starve the async runtime.
//!
//! Story 7.6b round-1 review re-triage: the per-helper logic was
//! extracted to `keyring_shared.rs` because it was identical across
//! `macos.rs` / `linux.rs` / `windows.rs`. This file now only holds
//! the trait dispatch and the macOS-specific `BACKEND` literal.

#![cfg(target_os = "macos")]

use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::keyring_shared as shared;
use crate::{
    DeleteOutcome, KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_PREVIOUS_ACCOUNT,
};

const BACKEND: &str = "apple";

/// macOS Keychain Services adapter. Holds no state — each operation
/// constructs a fresh `keyring::Entry` for the single master-key
/// entry.
pub struct MacKeyStore {
    _private: (),
}

impl MacKeyStore {
    /// Construct and probe the keychain backend.
    ///
    /// Returns `Err(BackendUnavailable)` if the backend cannot be
    /// reached. Makes `FallbackMode::Auto` functional.
    pub fn new() -> Result<Self, KeyStoreError> {
        shared::probe_backend(BACKEND, MASTER_KEY_ACCOUNT)?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for MacKeyStore {
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
        tokio::task::spawn_blocking(|| {
            shared::fetch_or_create_master_key_at_account(BACKEND, MASTER_KEY_ACCOUNT)
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        // Wrap in Zeroizing so the closure's copy is wiped when the
        // spawn_blocking task finishes, not left on the heap.
        let key_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*key);
        tokio::task::spawn_blocking(move || {
            shared::set_and_verify_at_account(
                BACKEND,
                MASTER_KEY_ACCOUNT,
                &key_copy,
                "set_master_key read-back did not match written value",
            )
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::delete_account(BACKEND, MASTER_KEY_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError> {
        let prev_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*previous);
        tokio::task::spawn_blocking(move || {
            shared::set_and_verify_at_account(
                BACKEND,
                MASTER_KEY_PREVIOUS_ACCOUNT,
                &prev_copy,
                "previous-slot read-back did not match written value",
            )
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::read_account(BACKEND, MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::clear_account(BACKEND, MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }
}
