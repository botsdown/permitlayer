//! Master key lifecycle and seal/unseal operations for permitlayer credentials.
//!
//! The vault is the sole surface that holds the master key and performs
//! seal/unseal. The storage layer is structurally incapable of observing
//! plaintext credentials.
//!
//! # Modules (Story 7.6)
//!
//! - [`seal`] — `Vault` struct + per-service HKDF-SHA256 seal/unseal
//!   (Story 1.3 surface).
//! - [`master_key`] — `MasterKey` newtype + `OsRng`-backed `generate` +
//!   one-way HMAC-SHA256 fingerprint (Story 7.6).
//! - [`rotation`] — single-frame `reseal` for `agentsso rotate-key`;
//!   plaintext is confined to one stack frame and never crosses an
//!   `OAuthToken` / `OAuthRefreshToken` boundary (Story 7.6).

#![forbid(unsafe_code)]

pub mod error;
pub mod master_key;
pub mod rotation;
pub mod seal;

pub use error::VaultError;
pub use master_key::MasterKey;
pub use rotation::{VaultRotationError, reseal};
pub use seal::Vault;
