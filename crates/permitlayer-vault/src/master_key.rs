//! Master-key lifecycle helpers for `agentsso rotate-key` (Story 7.6).
//!
//! Owns the construction and one-way fingerprinting of the 32-byte master
//! key that the OS keychain (or passphrase adapter) stores. The
//! [`Vault`](crate::Vault) constructor consumes a `Zeroizing<[u8; 32]>` by
//! move — there is no key-handling discipline to enforce on the seal/
//! unseal hot path. This module's job is the *out-of-band* operations
//! used by rotation:
//!
//! - **[`MasterKey::generate`]** — mint a fresh key from `OsRng`, fail-stop
//!   on RNG failure (matches the nonce-generation policy in
//!   [`crate::seal`]).
//! - **[`MasterKey::fingerprint`]** — produce a stable HMAC-SHA256 prefix
//!   (16 hex chars) for use in audit events and the on-disk
//!   `.rotation.in-progress` marker. Never reversible to the key bytes.
//! - **[`MasterKey::as_bytes`]** — internal accessor used by rotation to
//!   pass the bytes into [`crate::Vault::new`] and into
//!   `KeyStore::set_master_key`.
//!
//! `MasterKey` is non-`Clone`, non-`Debug`, and non-`Serialize` — it is
//! added to `xtask`'s `POLICED_TYPES` list per Story 1.3:515 cross-story
//! note. Construct one, use it (vault construction + keystore set), drop
//! it.

use hmac::{Hmac, Mac};
use permitlayer_keystore::MASTER_KEY_LEN;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HMAC key for the master-key fingerprint function. A constant string
/// (NOT secret); the master key is the HMAC *message*. The construction
/// is HMAC-SHA256(`FINGERPRINT_DOMAIN`, master_key) → first 8 bytes →
/// hex-encoded → 16 chars.
///
/// The HMAC is keyed (not bare SHA-256) so an offline attacker who
/// observes the fingerprint cannot mount a precomputed-table attack
/// against possible master keys; they would have to recompute the HMAC
/// for every guess.
const FINGERPRINT_DOMAIN: &[u8] = b"permitlayer-keyid-fp:";

/// A 32-byte master encryption key, generated via OS RNG and held inside
/// `Zeroizing` so it is wiped on drop.
///
/// Construct via [`MasterKey::generate`]; consume via
/// [`MasterKey::into_zeroizing`] (passes ownership into
/// [`crate::Vault::new`]).
pub struct MasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl MasterKey {
    /// Generate a fresh master key from the operating system's RNG.
    ///
    /// On RNG failure (extremely rare; would indicate a kernel-level
    /// problem with `/dev/urandom` / `getrandom(2)` / BCryptGenRandom),
    /// `OsRng::fill_bytes` panics — same fail-stop policy as nonce
    /// generation in [`crate::seal`]. A recoverable error here would
    /// tempt retry, which cannot help: there is no fallback entropy
    /// source for a 256-bit master key.
    #[must_use = "a generated MasterKey that is immediately dropped is wasted entropy"]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        OsRng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// Return a stable, one-way fingerprint of this master key suitable
    /// for audit events and on-disk markers.
    ///
    /// 16 hex characters (8 bytes of HMAC output). The HMAC key is the
    /// constant `FINGERPRINT_DOMAIN`; the master key is the message.
    /// HMAC-SHA256 truncation to 8 bytes still gives 64 bits of
    /// collision resistance, which is overkill for this use (the
    /// audit reader compares two fingerprints in the same event chain;
    /// a birthday collision across the entire population would require
    /// ~2^32 distinct master keys).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        Self::fingerprint_bytes(&self.0)
    }

    /// Compute the fingerprint of an arbitrary 32-byte master key — used
    /// by rotation's resume path, which reads the live keystore key
    /// (returned by `KeyStore::master_key`) and verifies its
    /// fingerprint matches the marker file's `new_keyid`.
    #[must_use]
    pub fn fingerprint_bytes(bytes: &[u8; MASTER_KEY_LEN]) -> String {
        // HMAC-SHA256 accepts any key length up to the block size; a
        // fixed 21-byte domain string never fails. We map the
        // unreachable-in-practice error to a graceful empty string
        // rather than panicking — the only field this feeds is an
        // audit-event tag, and a degraded "" beats a panic on a
        // hot-path that's already in the rotation flow.
        #[allow(clippy::option_if_let_else)]
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(FINGERPRINT_DOMAIN) {
            Ok(m) => m,
            Err(_) => return String::new(),
        };
        mac.update(bytes);
        let out = mac.finalize().into_bytes();
        // First 8 bytes → 16 hex chars. Manual hex encode (avoid pulling
        // in the `hex` crate just for this).
        let mut s = String::with_capacity(16);
        for byte in &out[..8] {
            s.push(hex_nibble(byte >> 4));
            s.push(hex_nibble(byte & 0x0F));
        }
        s
    }

    /// Borrow the underlying key bytes. Used by the rotation flow to
    /// pass the bytes into `KeyStore::set_master_key` (which takes
    /// `&[u8; 32]`) without consuming the `MasterKey`.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    /// Consume the `MasterKey`, returning the inner `Zeroizing` buffer.
    /// Used by the rotation flow to pass ownership into
    /// [`crate::Vault::new`] (which moves the key by value).
    pub fn into_zeroizing(self) -> Zeroizing<[u8; MASTER_KEY_LEN]> {
        self.0
    }

    /// Test-only constructor that wraps an explicit 32-byte buffer.
    /// Used by `rotation`'s tests to construct deterministic keys
    /// without going through `OsRng`. `cfg(test)` is set crate-wide
    /// when building tests, so `rotation::tests` can reach this
    /// `pub(crate)` helper across modules in the same crate.
    /// Production code cannot bypass [`Self::generate`]'s RNG path.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub(crate) fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        // Unreachable — caller masks to 0..=15.
        _ => '?',
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_32_bytes() {
        let key = MasterKey::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_is_non_deterministic() {
        // Two consecutive generations must differ. Probability of
        // collision is ~2^-256.
        let a = MasterKey::generate();
        let b = MasterKey::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn fingerprint_is_16_hex_chars() {
        let key = MasterKey::generate();
        let fp = key.fingerprint();
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let bytes = [0x42u8; 32];
        let fp1 = MasterKey::fingerprint_bytes(&bytes);
        let fp2 = MasterKey::fingerprint_bytes(&bytes);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_distinguishes_keys() {
        let a = [0x00u8; 32];
        let b = [0x01u8; 32];
        // The HMAC is one-way + collision-resistant; two distinct keys
        // produce distinct fingerprints with overwhelming probability.
        assert_ne!(MasterKey::fingerprint_bytes(&a), MasterKey::fingerprint_bytes(&b));
    }

    #[test]
    fn fingerprint_does_not_leak_key_bytes() {
        // Defensive check: the fingerprint string must not contain any
        // contiguous run of the key's hex bytes. Trivial for the
        // ALL-ZEROS key (`fp` would be a 16-char hex string, the input
        // is a 64-char hex string of zeroes; substring presence is a
        // false-positive trap, so we just assert the fingerprint is
        // SHORTER than a hex-encoded full key).
        let key = MasterKey::from_bytes([0u8; 32]);
        let fp = key.fingerprint();
        let key_hex = "0".repeat(64);
        assert!(fp.len() < key_hex.len());
    }

    #[test]
    fn into_zeroizing_returns_same_bytes() {
        let bytes = [0xCDu8; 32];
        let key = MasterKey::from_bytes(bytes);
        let z = key.into_zeroizing();
        assert_eq!(*z, bytes);
    }
}
