//! Root-owned mappings from kernel local principals to PermitLayer agents.
//!
//! These records contain no reusable credential. They authorize a local OS
//! account, authenticated by a platform peer-credential API, to act as one
//! existing PermitLayer agent on a narrowly scoped data-plane listener.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::store::StoreError;

/// Current local-principal record schema.
pub const LOCAL_PRINCIPAL_SCHEMA_VERSION: u16 = 3;

/// A fixed-function operation a kernel-authenticated local account may use.
/// These are deliberately narrower than connector scopes: possessing a local
/// socket never grants generic REST or MCP access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalCapability {
    DriveUpload,
    DriveDownload,
    DriveReplace,
    McpGmail,
    McpCalendar,
    McpDrive,
}

impl LocalCapability {
    /// Stable CLI/control-plane spelling for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DriveUpload => "drive-upload",
            Self::DriveDownload => "drive-download",
            Self::DriveReplace => "drive-replace",
            Self::McpGmail => "mcp-gmail",
            Self::McpCalendar => "mcp-calendar",
            Self::McpDrive => "mcp-drive",
        }
    }
}

/// Human-facing consent profile. The version and explicit capability list are
/// both persisted: a future release cannot reinterpret a profile name to add
/// authority without a new operator action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccessProfile {
    pub name: String,
    pub version: u16,
}

/// One kernel-identity-to-agent authorization grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Explicit fixed-function operations. Version-1 records did not contain
    /// this field and deserialize as upload-only, preserving their authority.
    pub capabilities: Vec<LocalCapability>,
    /// Exact connection IDs this local principal may address. Empty is retained
    /// only for legacy schema v1/v2 records and never authorizes MCP routes.
    pub connection_ids: Vec<String>,
    /// Optional versioned UX profile; capabilities remain authoritative.
    pub profile: Option<LocalAccessProfile>,
    /// Grant timestamp.
    pub granted_at: DateTime<Utc>,
    /// Kernel peer UID of the operator who issued the control-plane grant.
    pub granted_by_peer_uid: Option<u32>,
}

#[derive(Deserialize)]
struct LocalPrincipalWire {
    schema_version: u16,
    platform: String,
    uid: u32,
    username_at_grant: String,
    agent: String,
    capabilities: Option<Vec<LocalCapability>>,
    connection_ids: Option<Vec<String>>,
    profile: Option<LocalAccessProfile>,
    granted_at: DateTime<Utc>,
    granted_by_peer_uid: Option<u32>,
}

impl<'de> Deserialize<'de> for LocalPrincipal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LocalPrincipalWire::deserialize(deserializer)?;
        let capabilities = match (wire.schema_version, wire.capabilities) {
            (1, None) => vec![LocalCapability::DriveUpload],
            (_, Some(capabilities)) => capabilities,
            (_, None) => Vec::new(),
        };
        Ok(Self {
            schema_version: wire.schema_version,
            platform: wire.platform,
            uid: wire.uid,
            username_at_grant: wire.username_at_grant,
            agent: wire.agent,
            capabilities,
            connection_ids: wire.connection_ids.unwrap_or_default(),
            profile: wire.profile,
            granted_at: wire.granted_at,
            granted_by_peer_uid: wire.granted_by_peer_uid,
        })
    }
}

impl LocalPrincipal {
    #[must_use]
    pub fn permits(&self, capability: LocalCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    #[must_use]
    pub fn permits_connection(&self, connection_id: &str) -> bool {
        self.connection_ids.iter().any(|allowed| allowed == connection_id)
    }

    /// Validate the immutable capability contract named by a UX profile.
    /// The explicit capability vector remains authoritative; this prevents a
    /// profile label from becoming misleading or gaining new meaning later.
    #[must_use]
    pub fn profile_contract_matches(&self) -> bool {
        let Some(profile) = &self.profile else { return true };
        let mut capabilities = self.capabilities.clone();
        capabilities.sort_unstable();
        match (profile.name.as_str(), profile.version) {
            ("drive-read", 1) => capabilities == [LocalCapability::DriveDownload],
            ("drive-read-write", 1) => {
                capabilities == [LocalCapability::DriveUpload, LocalCapability::DriveDownload]
            }
            ("drive-full-control", 1) => {
                capabilities
                    == [
                        LocalCapability::DriveUpload,
                        LocalCapability::DriveDownload,
                        LocalCapability::DriveReplace,
                    ]
            }
            ("hermes-standard", 1) => {
                let has_mcp = capabilities.iter().any(|capability| {
                    matches!(
                        capability,
                        LocalCapability::McpGmail
                            | LocalCapability::McpCalendar
                            | LocalCapability::McpDrive
                    )
                });
                let has_drive_mcp = capabilities.contains(&LocalCapability::McpDrive);
                let drive_transfers = [
                    LocalCapability::DriveUpload,
                    LocalCapability::DriveDownload,
                    LocalCapability::DriveReplace,
                ];
                let has_download = capabilities.contains(&LocalCapability::DriveDownload);
                let has_upload = capabilities.contains(&LocalCapability::DriveUpload);
                let has_replace = capabilities.contains(&LocalCapability::DriveReplace);
                has_mcp
                    && if has_drive_mcp {
                        has_download && (!has_replace || has_upload)
                    } else {
                        drive_transfers.iter().all(|capability| !capabilities.contains(capability))
                    }
            }
            _ => false,
        }
    }
}

/// Persist local-principal authorization records keyed by kernel UID.
#[async_trait::async_trait]
pub trait LocalPrincipalStore: Send + Sync {
    /// Create a new UID mapping without overwriting an existing grant.
    async fn grant(&self, principal: LocalPrincipal) -> Result<(), StoreError>;

    /// Atomically replace an existing grant for the same UID. Callers must
    /// verify the kernel identity and agent are unchanged before widening
    /// capabilities.
    async fn replace(&self, principal: LocalPrincipal) -> Result<(), StoreError>;

    /// Resolve one UID. Absence is an authorization denial, not a store error.
    async fn get(&self, uid: u32) -> Result<Option<LocalPrincipal>, StoreError>;

    /// List every grant, sorted by UID by production implementations.
    async fn list(&self) -> Result<Vec<LocalPrincipal>, StoreError>;

    /// Revoke one UID mapping. Returns whether a mapping existed.
    async fn revoke(&self, uid: u32) -> Result<bool, StoreError>;
}
