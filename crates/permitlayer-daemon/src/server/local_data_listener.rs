//! Secretless, upload-only local data plane for macOS.
//!
//! One mode-0600 Unix socket is owned by each granted local UID. The socket
//! inode is only a coarse filesystem gate: every request is authenticated
//! again with `LOCAL_PEERCRED`, resolved through the root-private
//! `LocalPrincipalStore`, and then sent through the normal kill, policy,
//! connection-tracking, and audit middleware.

#![cfg(target_os = "macos")]

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use nix::unistd::{Gid, Uid, User, chown};
use permitlayer_core::agent::AgentRegistry;
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::killswitch::KillSwitch;
use permitlayer_core::policy::PolicySet;
use permitlayer_core::store::{
    AgentIdentityStore, BindingStore, ConnectionStore, LocalPrincipalStore,
};
use permitlayer_proxy::error::{AgentId, AgentPolicyBinding};
use permitlayer_proxy::middleware::{ApprovalService, ConnTrackerSink};
use tokio::net::UnixListener;
use tower::{Layer, Service};

use super::PeerCredentials;
use super::control_listener::UdsConnectInfo;

const RECONCILE_INTERVAL: Duration = Duration::from_millis(250);

/// Dependencies shared by every per-user upload listener.
#[derive(Clone)]
pub struct LocalUploadContext {
    pub routes: Router,
    pub store: Arc<dyn LocalPrincipalStore>,
    pub binding_store: Option<Arc<dyn BindingStore>>,
    pub connection_store: Option<Arc<dyn ConnectionStore>>,
    pub agent_store: Option<Arc<dyn AgentIdentityStore>>,
    pub agent_registry: Arc<AgentRegistry>,
    pub kill_switch: Arc<KillSwitch>,
    pub policy_set: Arc<ArcSwap<PolicySet>>,
    pub audit_dispatcher: Arc<AuditDispatcher>,
    pub approval_service: Arc<dyn ApprovalService>,
    pub approval_timeout: Arc<AtomicU64>,
    pub conn_tracker: Arc<dyn ConnTrackerSink>,
}

#[derive(Clone)]
struct LocalPeerAuthState {
    expected_uid: u32,
    store: Arc<dyn LocalPrincipalStore>,
    binding_store: Option<Arc<dyn BindingStore>>,
    connection_store: Option<Arc<dyn ConnectionStore>>,
    agent_store: Option<Arc<dyn AgentIdentityStore>>,
    agent_registry: Arc<AgentRegistry>,
    audit_dispatcher: Arc<AuditDispatcher>,
}

#[derive(Clone)]
struct LocalRequestAudit {
    request_id: String,
    path: String,
    method: String,
    selector: String,
}

impl LocalRequestAudit {
    fn capture(request: &Request) -> Self {
        Self {
            request_id: request
                .extensions()
                .get::<permitlayer_proxy::error::RequestId>()
                .map(|id| id.0.clone())
                .unwrap_or_else(|| ulid::Ulid::new().to_string()),
            path: request.uri().path().to_owned(),
            method: request.method().as_str().to_owned(),
            selector: selector_from_upload_path(request.uri().path())
                .unwrap_or_else(|| "-".to_owned()),
        }
    }
}

#[derive(Clone)]
struct LocalPeerAuthLayer {
    state: LocalPeerAuthState,
}

impl LocalPeerAuthLayer {
    fn new(state: LocalPeerAuthState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for LocalPeerAuthLayer {
    type Service = LocalPeerAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LocalPeerAuthService { inner, state: self.state.clone() }
    }
}

#[derive(Clone)]
struct LocalPeerAuthService<S> {
    inner: S,
    state: LocalPeerAuthState,
}

impl<S> Service<Request> for LocalPeerAuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let state = self.state.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            match authenticate_local_peer(state, request).await {
                Ok(request) => inner.call(request).await,
                Err(response) => Ok(*response),
            }
        })
    }
}

struct ActiveListener {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

/// Start a reconciler which makes the listener set converge on the
/// root-private grant store. Revocation takes effect immediately at the
/// request gate; socket removal follows within one reconcile interval.
pub async fn spawn_local_upload_reconciler(
    context: LocalUploadContext,
    home_override: Option<PathBuf>,
    mut drain: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut active = HashMap::<u32, ActiveListener>::new();
        reconcile(&context, home_override.as_deref(), &drain, &mut active).await;

        loop {
            tokio::select! {
                changed = drain.changed() => {
                    if changed.is_err() || *drain.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(RECONCILE_INTERVAL) => {
                    reconcile(&context, home_override.as_deref(), &drain, &mut active).await;
                }
            }
        }

        // Each serve task observes the same level-triggered drain channel.
        // Await them so audit-producing requests finish before the daemon
        // drains its audit dispatcher.
        for (_, listener) in active {
            if let Err(error) = listener.task.await {
                tracing::warn!(error = %error, "local upload listener task join failed");
            }
            unlink_socket(&listener.path);
        }
    })
}

async fn reconcile(
    context: &LocalUploadContext,
    home_override: Option<&Path>,
    drain: &tokio::sync::watch::Receiver<bool>,
    active: &mut HashMap<u32, ActiveListener>,
) {
    let grants = match context.store.list().await {
        Ok(grants) => grants,
        Err(error) => {
            tracing::error!(error = %error, "cannot reconcile local upload listeners; existing request gates remain fail-closed");
            return;
        }
    };
    let desired: HashSet<u32> = grants.iter().map(|grant| grant.uid).collect();

    // A serve task can end independently (accept error, resource pressure).
    // Remove it from the active set so this same reconciliation pass can
    // rebind instead of treating a dead task as a live authorization path.
    let finished: Vec<u32> = active
        .iter()
        .filter_map(|(uid, listener)| listener.task.is_finished().then_some(*uid))
        .collect();
    for uid in finished {
        if let Some(listener) = active.remove(&uid) {
            if let Err(error) = listener.task.await {
                tracing::warn!(uid, error = %error, "failed local upload listener task ended");
            }
            unlink_socket(&listener.path);
        }
    }

    let revoked: Vec<u32> = active.keys().copied().filter(|uid| !desired.contains(uid)).collect();
    for uid in revoked {
        if let Some(listener) = active.remove(&uid) {
            listener.task.abort();
            let _ = listener.task.await;
            unlink_socket(&listener.path);
            tracing::info!(uid, path = %listener.path.display(), "local upload listener revoked");
        }
    }

    for grant in grants {
        if active.contains_key(&grant.uid) {
            continue;
        }
        let path = permitlayer_core::paths::local_agent_socket_path(home_override, grant.uid);
        match bind_local_listener(&path, grant.uid, home_override.is_none()) {
            Ok(listener) => {
                let router = router_for_uid(context, grant.uid);
                let mut listener_drain = drain.clone();
                let serve_path = path.clone();
                let task = tokio::spawn(async move {
                    let graceful = async move {
                        if !*listener_drain.borrow() {
                            let _ = listener_drain.changed().await;
                        }
                    };
                    if let Err(error) = axum::serve(
                        listener,
                        router.into_make_service_with_connect_info::<UdsConnectInfo>(),
                    )
                    .with_graceful_shutdown(graceful)
                    .await
                    {
                        tracing::error!(error = %error, path = %serve_path.display(), "local upload listener failed");
                    }
                });
                tracing::info!(
                    uid = grant.uid,
                    agent = %grant.agent,
                    path = %path.display(),
                    "secretless local upload listener ready"
                );
                active.insert(grant.uid, ActiveListener { path, task });
            }
            Err(error) => {
                tracing::error!(uid = grant.uid, path = %path.display(), error = %error, "failed to bind local upload listener");
            }
        }
    }
}

fn router_for_uid(context: &LocalUploadContext, expected_uid: u32) -> Router {
    let auth_state = LocalPeerAuthState {
        expected_uid,
        store: Arc::clone(&context.store),
        binding_store: context.binding_store.clone(),
        connection_store: context.connection_store.clone(),
        agent_store: context.agent_store.clone(),
        agent_registry: Arc::clone(&context.agent_registry),
        audit_dispatcher: Arc::clone(&context.audit_dispatcher),
    };
    let middleware = permitlayer_proxy::middleware::assemble_authenticated_transport(
        LocalPeerAuthLayer::new(auth_state),
        Arc::clone(&context.kill_switch),
        Arc::clone(&context.policy_set),
        Arc::clone(&context.audit_dispatcher),
        Arc::clone(&context.approval_service),
        Arc::clone(&context.approval_timeout),
        Arc::clone(&context.conn_tracker),
    );
    context.routes.clone().layer(middleware)
}

async fn authenticate_local_peer(
    state: LocalPeerAuthState,
    mut request: Request,
) -> Result<Request, Box<Response>> {
    let audit = LocalRequestAudit::capture(&request);
    let peer = match request.extensions().get::<ConnectInfo<UdsConnectInfo>>() {
        Some(connect) => connect.0.peer,
        None => {
            return Err(Box::new(
                local_auth_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &state,
                    &audit,
                    PeerCredentials { uid: u32::MAX, gid: u32::MAX },
                    None,
                    "local_access.peer_unavailable",
                    "kernel peer credentials are unavailable",
                )
                .await,
            ));
        }
    };
    if peer.uid == u32::MAX {
        return Err(Box::new(
            local_auth_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                &state,
                &audit,
                peer,
                None,
                "local_access.peer_unavailable",
                "the daemon could not read kernel peer credentials",
            )
            .await,
        ));
    }
    if peer.uid < 501 || peer.uid != state.expected_uid {
        return Err(Box::new(
            local_auth_denied(
                &state,
                &audit,
                peer,
                None,
                "local_access.peer_mismatch",
                "kernel peer UID does not own this upload socket",
            )
            .await,
        ));
    }
    let grant = match state.store.get(peer.uid).await {
        Ok(Some(grant)) if grant.uid == state.expected_uid => grant,
        Ok(_) => {
            return Err(Box::new(
                local_auth_denied(
                    &state,
                    &audit,
                    peer,
                    None,
                    "local_access.not_granted",
                    "this macOS user has no active PermitLayer local-access grant",
                )
                .await,
            ));
        }
        Err(error) => {
            tracing::error!(uid = peer.uid, error = %error, "local-principal lookup failed closed");
            return Err(Box::new(
                local_auth_denied(
                    &state,
                    &audit,
                    peer,
                    None,
                    "local_access.store_unavailable",
                    "the daemon could not verify the local-access grant",
                )
                .await,
            ));
        }
    };

    match User::from_uid(Uid::from_raw(peer.uid)) {
        Ok(Some(user)) if user.name == grant.username_at_grant => {}
        Ok(Some(_)) => {
            return Err(Box::new(local_auth_denied(
                &state,
                &audit,
                peer,
                Some(&grant.agent),
                "local_access.username_drift",
                "the UID now resolves to a different macOS account; an operator must revoke and re-grant local access",
            )
            .await));
        }
        Ok(None) | Err(_) => {
            return Err(Box::new(
                local_auth_denied(
                    &state,
                    &audit,
                    peer,
                    Some(&grant.agent),
                    "local_access.user_unavailable",
                    "the daemon could not verify the granted macOS account",
                )
                .await,
            ));
        }
    }

    let mut identity = match state.agent_registry.snapshot().get_by_name(&grant.agent).cloned() {
        Some(identity) => identity,
        None => {
            return Err(Box::new(
                local_auth_denied(
                    &state,
                    &audit,
                    peer,
                    Some(&grant.agent),
                    "local_access.agent_unavailable",
                    "the locally granted PermitLayer agent no longer exists",
                )
                .await,
            ));
        }
    };
    let selector = match selector_from_upload_path(request.uri().path()) {
        Some(selector) => selector,
        None => {
            return Err(Box::new(
                local_auth_denied(
                    &state,
                    &audit,
                    peer,
                    Some(&grant.agent),
                    "local_access.route_denied",
                    "the local data socket accepts Drive upload routes only",
                )
                .await,
            ));
        }
    };
    let policy = match permitlayer_proxy::middleware::auth::resolve_local_policy_binding(
        state.binding_store.as_ref(),
        state.connection_store.as_ref(),
        &grant.agent,
        &selector,
    )
    .await
    {
        Ok(policy) => policy,
        Err(error) => {
            emit_local_peer_audit(
                &state,
                &audit,
                peer,
                &grant.agent,
                "denied",
                "local-peer-denied",
                Some("local_access.policy_resolution_failed"),
            )
            .await;
            return Err(Box::new(error.into_response()));
        }
    };

    // Never accept caller-declared authority. The listener itself fixes the
    // only available scope, and there is deliberately no bearer fallback.
    request.headers_mut().insert("x-agentsso-scope", HeaderValue::from_static("drive.file"));
    request.extensions_mut().insert(AgentId(grant.agent.clone()));
    request.extensions_mut().insert(AgentPolicyBinding(policy));
    request.extensions_mut().insert(PeerCredentials { uid: peer.uid, gid: peer.gid });
    emit_local_peer_audit(
        &state,
        &audit,
        peer,
        &grant.agent,
        "ok",
        "local-peer-authenticated",
        None,
    )
    .await;
    let now = chrono::Utc::now();
    state.agent_registry.touch_last_seen(&grant.agent, now);
    if let Some(store) = state.agent_store {
        let agent = grant.agent.clone();
        identity.last_seen_at = Some(now);
        tokio::spawn(async move {
            if let Err(error) = store.touch_last_seen(identity).await {
                tracing::warn!(agent, error = %error, "local peer last_seen persistence failed");
            }
        });
    }
    Ok(request)
}

fn selector_from_upload_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v1/tools/")?;
    let (selector, suffix) = rest.split_once('/')?;
    if selector.is_empty() || (suffix != "uploads" && !suffix.starts_with("uploads/")) {
        return None;
    }
    urlencoding::decode(selector).ok().map(|value| value.into_owned())
}

async fn local_auth_denied(
    state: &LocalPeerAuthState,
    audit: &LocalRequestAudit,
    peer: PeerCredentials,
    agent: Option<&str>,
    code: &str,
    message: &str,
) -> Response {
    local_auth_failure(StatusCode::FORBIDDEN, state, audit, peer, agent, code, message).await
}

async fn local_auth_failure(
    status: StatusCode,
    state: &LocalPeerAuthState,
    audit: &LocalRequestAudit,
    peer: PeerCredentials,
    agent: Option<&str>,
    code: &str,
    message: &str,
) -> Response {
    emit_local_peer_audit(
        state,
        audit,
        peer,
        agent.unwrap_or("unmapped-local-peer"),
        "denied",
        "local-peer-denied",
        Some(code),
    )
    .await;
    (
        status,
        axum::Json(serde_json::json!({
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

async fn emit_local_peer_audit(
    state: &LocalPeerAuthState,
    audit: &LocalRequestAudit,
    peer: PeerCredentials,
    agent: &str,
    outcome: &str,
    event_type: &str,
    reason: Option<&str>,
) {
    let mut event = permitlayer_core::audit::event::AuditEvent::with_request_id(
        audit.request_id.clone(),
        agent.to_owned(),
        "google-drive".to_owned(),
        "drive.file".to_owned(),
        audit.path.clone(),
        outcome.to_owned(),
        event_type.to_owned(),
    );
    event.extra = serde_json::json!({
        "peer_uid": peer.uid,
        "peer_gid": peer.gid,
        "connection_selector": audit.selector,
        "method": audit.method,
        "reason": reason,
    });
    state.audit_dispatcher.dispatch(event).await;
}

fn bind_local_listener(path: &Path, uid: u32, apply_owner: bool) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        if apply_owner {
            let metadata = std::fs::symlink_metadata(parent)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upload socket parent must be a root-owned, non-symlink directory not writable by group or other",
                ));
            }
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload socket path is a symlink",
            ));
        }
        Ok(metadata) if !metadata.file_type().is_socket() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload socket path is not a socket",
            ));
        }
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "upload socket already has a listener",
                ));
            }
            Err(_) => std::fs::remove_file(path)?,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = permitlayer_platform_macos::with_umask(0o177, || UnixListener::bind(path))?;
    let permission_result = if apply_owner {
        let user = User::from_uid(Uid::from_raw(uid))
            .map_err(|error| io::Error::other(format!("resolve uid {uid}: {error}")))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("uid {uid} no longer exists"))
            })?;
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(user.gid.as_raw())))
            .map_err(|error| io::Error::other(format!("chown upload socket to uid {uid}: {error}")))
            .and_then(|()| std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)))
    } else {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    };
    if let Err(error) = permission_result {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(listener);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    };
    let expected_owner = if apply_owner { uid } else { nix::unistd::geteuid().as_raw() };
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upload socket ownership/mode verification failed",
        ));
    }
    Ok(listener)
}

fn unlink_socket(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if let Err(error) = std::fs::remove_file(path) {
                tracing::warn!(path = %path.display(), error = %error, "failed to remove local upload socket");
            }
        }
        Ok(_) => {
            tracing::error!(path = %path.display(), "refusing to unlink non-socket at local upload path")
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "cannot inspect local upload socket during cleanup")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt as _;
    use permitlayer_core::store::StoreError;
    use tower::ServiceExt as _;

    struct MemoryLocalStore(tokio::sync::RwLock<Option<permitlayer_core::store::LocalPrincipal>>);

    #[async_trait::async_trait]
    impl LocalPrincipalStore for MemoryLocalStore {
        async fn grant(
            &self,
            principal: permitlayer_core::store::LocalPrincipal,
        ) -> Result<(), StoreError> {
            *self.0.write().await = Some(principal);
            Ok(())
        }

        async fn get(
            &self,
            uid: u32,
        ) -> Result<Option<permitlayer_core::store::LocalPrincipal>, StoreError> {
            Ok(self.0.read().await.clone().filter(|grant| grant.uid == uid))
        }

        async fn list(&self) -> Result<Vec<permitlayer_core::store::LocalPrincipal>, StoreError> {
            Ok(self.0.read().await.clone().into_iter().collect())
        }

        async fn revoke(&self, uid: u32) -> Result<bool, StoreError> {
            let mut grant = self.0.write().await;
            let existed = grant.as_ref().is_some_and(|grant| grant.uid == uid);
            if existed {
                *grant = None;
            }
            Ok(existed)
        }
    }

    fn peer_auth_router(
        peer_uid: u32,
        expected_uid: u32,
        store: Arc<MemoryLocalStore>,
    ) -> (Router, HttpRequest<Body>) {
        let identity = permitlayer_core::agent::AgentIdentity::new(
            "angie".to_owned(),
            "unused".to_owned(),
            "00".repeat(32),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
        let state = LocalPeerAuthState {
            expected_uid,
            store,
            binding_store: None,
            connection_store: None,
            agent_store: None,
            agent_registry: Arc::new(AgentRegistry::new(vec![identity])),
            audit_dispatcher: Arc::new(AuditDispatcher::none()),
        };
        async fn handler(request: Request) -> Response {
            match request.extensions().get::<AgentId>() {
                Some(agent) => {
                    let scope = request
                        .headers()
                        .get("x-agentsso-scope")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing");
                    (StatusCode::OK, format!("{}|{scope}", agent.0)).into_response()
                }
                None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        let router = Router::new()
            .route("/v1/tools/{selector}/uploads", axum::routing::post(handler))
            .layer(LocalPeerAuthLayer::new(state));
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/tools/drive/uploads")
            .header("authorization", "Bearer malicious-caller-value")
            .header("x-agentsso-scope", "gmail.send")
            .header("x-agentsso-agent", "attacker-selected-agent")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(UdsConnectInfo {
            peer: PeerCredentials { uid: peer_uid, gid: 20 },
            sentinel_addr: "127.0.0.1:0".parse().unwrap(),
        }));
        (router, request)
    }

    fn current_username() -> String {
        User::from_uid(nix::unistd::geteuid()).unwrap().unwrap().name
    }

    #[test]
    fn accepts_only_upload_routes() {
        assert_eq!(selector_from_upload_path("/v1/tools/drive/uploads"), Some("drive".to_owned()));
        assert_eq!(
            selector_from_upload_path("/v1/tools/my%20drive/uploads/id"),
            Some("my drive".to_owned())
        );
        assert_eq!(selector_from_upload_path("/v1/tools/drive/files"), None);
        assert_eq!(selector_from_upload_path("/mcp/drive"), None);
    }

    #[tokio::test]
    async fn kernel_peer_grant_stamps_agent_without_a_bearer() {
        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(Some(
            permitlayer_core::store::LocalPrincipal {
                schema_version: 1,
                platform: "macos".to_owned(),
                uid,
                username_at_grant: current_username(),
                agent: "angie".to_owned(),
                granted_at: chrono::Utc::now(),
                granted_by_peer_uid: Some(0),
            },
        ))));
        let (router, request) = peer_auth_router(uid, uid, store);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"angie|drive.file");
    }

    #[tokio::test]
    async fn real_unix_transport_uses_kernel_peer_credentials() {
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;

        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(Some(
            permitlayer_core::store::LocalPrincipal {
                schema_version: 1,
                platform: "macos".to_owned(),
                uid,
                username_at_grant: current_username(),
                agent: "angie".to_owned(),
                granted_at: chrono::Utc::now(),
                granted_by_peer_uid: Some(0),
            },
        ))));
        let (router, _) = peer_auth_router(uid, uid, store);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        let listener = bind_local_listener(&path, uid, false).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<UdsConnectInfo>())
                .await
                .unwrap();
        });

        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/tools/drive/uploads")
            .header("host", "permitlayer.local")
            .header("authorization", "Bearer malicious-caller-value")
            .header("x-agentsso-scope", "gmail.send")
            .body(Body::empty())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"angie|drive.file");

        drop(sender);
        connection.await.unwrap();
        server.abort();
        let _ = server.await;
        unlink_socket(&path);
    }

    #[tokio::test]
    async fn wrong_kernel_peer_is_denied_even_when_a_grant_exists() {
        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(Some(
            permitlayer_core::store::LocalPrincipal {
                schema_version: 1,
                platform: "macos".to_owned(),
                uid,
                username_at_grant: current_username(),
                agent: "angie".to_owned(),
                granted_at: chrono::Utc::now(),
                granted_by_peer_uid: Some(0),
            },
        ))));
        let (router, request) = peer_auth_router(uid.saturating_add(1), uid, store);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn peer_credential_failure_sentinel_is_service_unavailable() {
        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(None)));
        let (router, request) = peer_auth_router(u32::MAX, uid, store);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn revoked_grant_is_denied_on_the_next_request() {
        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(None)));
        let (router, request) = peer_auth_router(uid, uid, store);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn username_drift_fails_closed() {
        let uid = nix::unistd::geteuid().as_raw();
        if uid < 501 {
            return;
        }
        let store = Arc::new(MemoryLocalStore(tokio::sync::RwLock::new(Some(
            permitlayer_core::store::LocalPrincipal {
                schema_version: 1,
                platform: "macos".to_owned(),
                uid,
                username_at_grant: "definitely-not-the-current-user".to_owned(),
                agent: "angie".to_owned(),
                granted_at: chrono::Utc::now(),
                granted_by_peer_uid: Some(0),
            },
        ))));
        let (router, request) = peer_auth_router(uid, uid, store);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bound_socket_is_private_to_its_owner() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        let listener = bind_local_listener(&path, nix::unistd::geteuid().as_raw(), false).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(listener);
        unlink_socket(&path);
    }
}
