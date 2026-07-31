//! Root-owned mappings from kernel local principals to PermitLayer agents.
//!
//! These records contain no reusable credential. They authorize a local OS
//! account, authenticated by a platform peer-credential API, to act as one
//! existing PermitLayer agent on a narrowly scoped data-plane listener.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::store::StoreError;

/// Current local-principal record schema.
pub const LOCAL_PRINCIPAL_SCHEMA_VERSION: u16 = 1;

/// One kernel-identity-to-agent authorization grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPrincipal {
    /// On-disk schema version. Unknown versions fail closed.
    pub schema_version: u16,
    /// Platform whose kernel identity namespace owns `uid`.
    pub platform: String,
    /// Kernel-attested effective user identifier.
    pub uid: u32,
    /// Username observed and resolved by the privileged daemon at grant time.
    pub username_at_grant: String,
    /// Existing PermitLayer agent used for binding and policy resolution.
    pub agent: String,
    /// Grant timestamp.
    pub granted_at: DateTime<Utc>,
    /// Kernel peer UID of the operator who issued the control-plane grant.
    pub granted_by_peer_uid: Option<u32>,
}

/// Persist local-principal authorization records keyed by kernel UID.
#[async_trait::async_trait]
pub trait LocalPrincipalStore: Send + Sync {
    /// Create a new UID mapping without overwriting an existing grant.
    async fn grant(&self, principal: LocalPrincipal) -> Result<(), StoreError>;

    /// Resolve one UID. Absence is an authorization denial, not a store error.
    async fn get(&self, uid: u32) -> Result<Option<LocalPrincipal>, StoreError>;

    /// List every grant, sorted by UID by production implementations.
    async fn list(&self) -> Result<Vec<LocalPrincipal>, StoreError>;

    /// Revoke one UID mapping. Returns whether a mapping existed.
    async fn revoke(&self, uid: u32) -> Result<bool, StoreError>;
}
