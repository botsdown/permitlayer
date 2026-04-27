//! Phase A→F atomic state machine for `agentsso rotate-key`.
//!
//! See the spec's Dev Notes "Order of operations is the load-bearing
//! invariant" for the recoverability table mapping every crash window
//! to a recovery path.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use permitlayer_core::store::CredentialStore;
use permitlayer_core::store::fs::CredentialFsStore;
use permitlayer_keystore::KeyStore;
use permitlayer_vault::{MasterKey, Vault, reseal};
use zeroize::Zeroizing;

use super::state::RotationMarker;
use super::{exit4, exit5, step_glyphs};

/// Run the Phase A→F rotation. Caller has already verified daemon is
/// stopped, brew-services not managing, keystore is native, and no
/// `.rotation.in-progress` marker exists.
pub(crate) async fn run_rotation(
    home: &Path,
    keystore: &dyn KeyStore,
    started: Instant,
) -> Result<()> {
    let g = step_glyphs();
    let vault_dir = home.join("vault");
    let store = CredentialFsStore::new(home.to_path_buf())
        .map_err(|e| anyhow::anyhow!("failed to construct credential store: {e}"))?;

    // ── Phase 0: read old master key + mint new master key ─────────
    let old_key_bytes = keystore.master_key().await.map_err(|e| {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_old_key_read_failed",
                &format!("could not read existing master key: {e}"),
                "verify your OS keychain is responsive (try `agentsso status`)",
                None,
            )
        );
        exit4()
    })?;
    let new_key = MasterKey::generate();
    let old_keyid = MasterKey::fingerprint_bytes(&old_key_bytes);
    let new_keyid = new_key.fingerprint();
    // Story 7.6a (review patch): this rotate-key surface is dormant
    // per Task 9 — the dispatcher refuses invocation until 7.6b
    // lands. Even so, we wire the call sites to `compute_active_key_id`
    // + (active + 1) so that flipping the dormancy fence in 7.6b
    // does NOT silently downgrade rotation tracking to `key_id = 0`.
    // The original review found this as a single-line-removal
    // footgun: `Vault::new(.., 0)` everywhere meant a future
    // de-dormant-ification would corrupt the monotonic key_id
    // invariant on first run. Stamping the correct values here means
    // the worst case in 7.6b is "we overwrite this code path
    // entirely" rather than "we ship a broken rotation."
    let active_key_id = super::super::start::compute_active_key_id(&vault_dir);
    let new_key_id = active_key_id.saturating_add(1);
    let old_vault = Vault::new(Zeroizing::new(*old_key_bytes), active_key_id);
    let new_vault = Vault::new(Zeroizing::new(*new_key.as_bytes()), new_key_id);

    tracing::info!(
        old_keyid = %old_keyid,
        new_keyid = %new_keyid,
        "minted new master key; entering Phase A (re-seal)"
    );

    // ── Phase A: re-seal alongside old ─────────────────────────────
    let services = store.list_services().await.map_err(|e| {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_list_services_failed",
                &format!("could not enumerate vault entries: {e}"),
                "check ~/.agentsso/vault/ permissions",
                None,
            )
        );
        exit5()
    })?;
    println!(
        "{} re-encrypting {} vault entries  {} writing .sealed.new files",
        g.arrow,
        services.len(),
        g.check
    );
    let mut staged: Vec<PathBuf> = Vec::with_capacity(services.len());
    for service in &services {
        let sealed_old = match store.get(service).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Race: list_services saw it but it's gone now. Skip.
                tracing::warn!(service, "vault entry vanished between list and get; skipping");
                continue;
            }
            Err(e) => {
                tracing::error!(service, error = %e, "failed to read vault entry during Phase A");
                cleanup_staged(&staged);
                eprint!(
                    "{}",
                    crate::design::render::error_block(
                        "rotate_key_phase_a_read_failed",
                        &format!("could not read vault entry '{service}': {e}"),
                        "check ~/.agentsso/vault/ permissions and re-run rotate-key",
                        None,
                    )
                );
                return Err(exit5());
            }
        };
        let resealed = match reseal(&old_vault, &new_vault, &sealed_old, service) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(service, error = %e, "reseal failed during Phase A");
                cleanup_staged(&staged);
                eprint!(
                    "{}",
                    crate::design::render::error_block(
                        "rotate_key_phase_a_reseal_failed",
                        &format!("reseal failed for '{service}': {e}"),
                        "vault entry may be corrupt; check ~/.agentsso/vault/ \
                         and re-run rotate-key after fixing",
                        None,
                    )
                );
                return Err(exit5());
            }
        };
        // Write to <vault>/<service>.sealed.new
        let staged_path = vault_dir.join(format!("{service}.sealed.new"));
        if let Err(e) = write_sealed_new_atomic(&staged_path, &resealed) {
            tracing::error!(service, error = %e, "failed to write .sealed.new during Phase A");
            cleanup_staged(&staged);
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_phase_a_write_failed",
                    &format!("could not stage re-encrypted entry for '{service}': {e}"),
                    "check disk space and ~/.agentsso/vault/ permissions",
                    None,
                )
            );
            return Err(exit5());
        }
        staged.push(staged_path);
    }

    // ── Phase B: write the .rotation.in-progress marker ────────────
    let sealed_count: u32 = staged.len().try_into().unwrap_or(u32::MAX);
    let marker = RotationMarker::new(old_keyid.clone(), new_keyid.clone(), sealed_count);
    if let Err(e) = marker.write_atomic(&vault_dir) {
        tracing::error!(error = %e, "failed to write rotation marker during Phase B");
        cleanup_staged(&staged);
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_phase_b_marker_write_failed",
                &format!("could not write rotation marker: {e}"),
                "check ~/.agentsso/vault/ permissions",
                None,
            )
        );
        return Err(exit5());
    }
    println!("{} writing rotation marker  {} {} entries staged", g.arrow, g.check, staged.len());

    // ── Phase C: keystore swap ─────────────────────────────────────
    //
    // Pivot point. Before this returns Ok, old vault still readable;
    // after, only new vault is readable. A crash AT this exact line
    // is recoverable both ways depending on whether the keystore
    // accepted the write.
    if let Err(e) = keystore.set_master_key(new_key.as_bytes()).await {
        tracing::error!(error = %e, "keystore set_master_key failed during Phase C");
        // Rollback: marker exists but keystore still has old key.
        // Delete marker + .sealed.new files; old vault is still
        // readable.
        let _ = std::fs::remove_file(RotationMarker::path(&vault_dir));
        cleanup_staged(&staged);
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_phase_c_keystore_swap_failed",
                &format!("could not write new master key to keystore: {e}"),
                "check OS keychain is responsive; rotation rolled back, old key preserved",
                None,
            )
        );
        return Err(exit4());
    }
    println!("{} swapping master key  {} keystore updated", g.arrow, g.check);

    // ── Phase D: rename .sealed.new → .sealed ──────────────────────
    //
    // Each rename is its own POSIX-atomic operation. A crash mid-
    // loop leaves SOME files renamed and others not; the resume
    // path picks up where we left off (idempotent — if `.sealed.new`
    // is gone, `.sealed` already has the new content).
    let mut rename_failures = 0u32;
    for staged_path in &staged {
        let live_path = staged_path.with_extension(""); // strip ".new"
        if let Err(e) = std::fs::rename(staged_path, &live_path) {
            // Already renamed by a prior partial run? If so, the live
            // file already has new content and the staged file is
            // gone — that's fine.
            if e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            tracing::error!(
                staged = %staged_path.display(),
                live = %live_path.display(),
                error = %e,
                "rename .sealed.new → .sealed failed during Phase D"
            );
            rename_failures += 1;
        }
    }
    if rename_failures > 0 {
        // Partial state. The marker is still on disk; the operator
        // can re-run `agentsso rotate-key` to complete.
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_phase_d_rename_failed",
                &format!(
                    "{rename_failures} rename(s) failed; rotation is partially complete. \
                     Re-run `agentsso rotate-key` to finish."
                ),
                "agentsso rotate-key",
                None,
            )
        );
        return Err(exit5());
    }
    println!("{} renaming staged files  {} {} entries promoted", g.arrow, g.check, staged.len());

    // ── Phase E: invalidate agent registry (Q4 option B) ───────────
    //
    // Per Q4 architectural-reality correction: agent `lookup_key_hex`
    // is computed from plaintext bearer token + master-derived
    // subkey, and the plaintext is not stored. Invalidate every
    // agent file; agents must re-run `agentsso agent register`.
    let agents_dir = home.join("agents");
    let agents_invalidated = invalidate_agent_registry(&agents_dir);
    if agents_invalidated > 0 {
        println!(
            "{} invalidating agent tokens  {} {} agent file(s) removed (re-register required)",
            g.arrow, g.check, agents_invalidated
        );
    } else {
        println!("{} invalidating agent tokens  {} no agents registered", g.arrow, g.check);
    }

    // ── Phase F: cleanup + audit + closing line ───────────────────
    let _ = std::fs::remove_file(RotationMarker::path(&vault_dir));
    let elapsed_ms = started.elapsed().as_millis() as u64;
    emit_master_key_rotated_audit(
        home,
        &old_keyid,
        &new_keyid,
        sealed_count,
        agents_invalidated,
        elapsed_ms,
    )
    .await;

    println!(
        "{} master key rotated  {} {} → {} ({} entries, {} agents invalidated, {}ms)",
        g.arrow, g.check, old_keyid, new_keyid, sealed_count, agents_invalidated, elapsed_ms
    );
    println!("  next: agentsso start    # bring the daemon back up");
    Ok(())
}

/// Best-effort cleanup of staged `.sealed.new` files on Phase A/B
/// failure. Each removal is independent; we log warnings for any
/// failure but do not bubble.
fn cleanup_staged(paths: &[PathBuf]) {
    for p in paths {
        if let Err(e) = std::fs::remove_file(p)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %p.display(),
                error = %e,
                "failed to clean up staged .sealed.new file"
            );
        }
    }
}

/// Write a `SealedCredential` to a `.sealed.new` path atomically.
/// Mirrors the `credential_fs::atomic_write_real` pattern.
fn write_sealed_new_atomic(
    target: &Path,
    sealed: &permitlayer_credential::SealedCredential,
) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other("sealed.new target has no parent dir"))?;
    std::fs::create_dir_all(parent)?;

    // Encode envelope using the same routine credential_fs uses.
    let bytes = permitlayer_core::store::fs::credential_fs::encode_envelope(sealed);

    let pid = std::process::id();
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("sealed.new target has no filename"))?;
    let tmp = parent.join(format!("{file_name}.tmp.{pid}"));

    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, target)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Delete every `*.toml` file under `<home>/agents/`. Used by Phase E
/// (Q4 option B). Returns the count of files removed for the audit
/// event. Tolerates the agents dir being absent (returns 0).
///
/// `pub(super)` so the resume path in `resume.rs` can call the same
/// implementation.
pub(super) fn invalidate_agent_registry(agents_dir: &Path) -> u32 {
    let mut removed = 0u32;
    let read_dir = match std::fs::read_dir(agents_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!(
                dir = %agents_dir.display(),
                error = %e,
                "failed to enumerate agents dir during Phase E"
            );
            return 0;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // Skip dotfiles + tempfiles. Only touch <name>.toml.
        if name.starts_with('.') || name.contains(".tmp.") {
            continue;
        }
        if !name.ends_with(".toml") {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove agent file during Phase E"
                );
            }
        }
    }
    removed
}

/// Emit the `master-key-rotated` audit event. Best-effort: an audit-
/// emit failure is logged via tracing but does not abort the
/// rotation (the rotation has already succeeded by this point — only
/// cleanup remains).
///
/// `pub(super)` so the resume path in `resume.rs` can emit the same
/// event after a successful resume.
///
/// Mirrors `cli::update::make_event` + `cli::update::emit` shape so
/// downstream `agentsso audit` consumers see the same envelope across
/// `update-*` and `master-key-*` events.
pub(super) async fn emit_master_key_rotated_audit(
    home: &Path,
    old_keyid: &str,
    new_keyid: &str,
    vault_reseal_count: u32,
    agents_invalidated: u32,
    elapsed_ms: u64,
) {
    use permitlayer_core::audit::event::AuditEvent;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::audit_fs::AuditFsStore;
    use std::sync::Arc;

    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(error = %e, "scrub engine init failed; skipping master-key-rotated audit event");
            return;
        }
    };
    let audit_dir = home.join("audit");
    let store = match AuditFsStore::new(audit_dir, 100_000_000, scrub_engine) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not construct audit store; skipping master-key-rotated event");
            return;
        }
    };

    let mut event = AuditEvent::new(
        "cli".into(),
        "rotate-key".into(),
        String::new(),
        "master-key".into(),
        "ok".into(),
        "master-key-rotated".into(),
    );
    event.extra = serde_json::json!({
        "old_keyid": old_keyid,
        "new_keyid": new_keyid,
        "kdf": "OsRng",
        "vault_reseal_count": vault_reseal_count,
        "agents_invalidated": agents_invalidated,
        "elapsed_ms": elapsed_ms,
    });

    if let Err(e) = store.append(event).await {
        tracing::warn!(error = %e, "failed to append master-key-rotated audit event");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn invalidate_agent_registry_removes_only_toml_files() {
        let tmp = TempDir::new().unwrap();
        let agents = tmp.path().join("agents");
        std::fs::create_dir_all(&agents).unwrap();

        // Three agent files, one dotfile, one tempfile, one non-toml.
        std::fs::write(agents.join("alice.toml"), "fake").unwrap();
        std::fs::write(agents.join("bob.toml"), "fake").unwrap();
        std::fs::write(agents.join("carol.toml"), "fake").unwrap();
        std::fs::write(agents.join(".DS_Store"), "fake").unwrap();
        std::fs::write(agents.join("alice.toml.tmp.123"), "fake").unwrap();
        std::fs::write(agents.join("readme.txt"), "fake").unwrap();

        let removed = invalidate_agent_registry(&agents);
        assert_eq!(removed, 3);

        // .toml files are gone; the others survive.
        assert!(!agents.join("alice.toml").exists());
        assert!(!agents.join("bob.toml").exists());
        assert!(!agents.join("carol.toml").exists());
        assert!(agents.join(".DS_Store").exists());
        assert!(agents.join("alice.toml.tmp.123").exists());
        assert!(agents.join("readme.txt").exists());

        // The dir itself is preserved (we don't `remove_dir_all`).
        assert!(agents.exists());
    }

    #[test]
    fn invalidate_agent_registry_returns_zero_when_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let agents = tmp.path().join("nonexistent-agents");
        let removed = invalidate_agent_registry(&agents);
        assert_eq!(removed, 0);
    }

    #[test]
    fn invalidate_agent_registry_returns_zero_when_dir_empty() {
        let tmp = TempDir::new().unwrap();
        let agents = tmp.path().join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        let removed = invalidate_agent_registry(&agents);
        assert_eq!(removed, 0);
    }

    #[test]
    fn write_sealed_new_atomic_writes_file_with_envelope_format() {
        use permitlayer_credential::OAuthToken;
        use permitlayer_vault::Vault;

        let tmp = TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        let vault = Vault::new(Zeroizing::new([0xAB; 32]), 0);
        let token = OAuthToken::from_trusted_bytes(b"hello-rotation".to_vec());
        let sealed = vault.seal("gmail", &token).unwrap();

        let target = vault_dir.join("gmail.sealed.new");
        write_sealed_new_atomic(&target, &sealed).unwrap();

        // File exists with the encoded envelope; can be decoded back.
        assert!(target.exists());
        let bytes = std::fs::read(&target).unwrap();
        // Story 7.6a bumped envelope schema 1 → 2; encode_envelope
        // always writes v2. The version u16 little-endian is 0x0002.
        assert_eq!(&bytes[..2], &[2u8, 0u8]);

        // Tempfile cleaned up.
        let leftovers: Vec<_> = std::fs::read_dir(&vault_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leaked tempfile: {leftovers:?}");
    }
}
