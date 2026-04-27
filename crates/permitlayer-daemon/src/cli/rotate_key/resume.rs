//! Crash-resume path for `agentsso rotate-key`.
//!
//! Runs when `<vault>/.rotation.in-progress` exists at rotate-key
//! entry. The marker file's `new_keyid` is matched against the
//! current keystore's master key fingerprint:
//!
//! - **Match (rotation completed Phase C, crashed in D/E/F):** finish
//!   Phases D/E/F under the new key (which is already in the
//!   keystore). Idempotent — re-running over a partially-finished
//!   state is safe.
//! - **Mismatch (rotation crashed before Phase C OR keystore was
//!   tampered with manually between runs):** refuse with a
//!   structured error and exit 5. Manual intervention required.
//!
//! See the spec's Dev Notes "Order of operations is the load-bearing
//! invariant" for the recoverability table.

use std::path::Path;

use anyhow::Result;
use permitlayer_keystore::KeyStore;
use permitlayer_vault::MasterKey;

use super::state::RotationMarker;
use super::{exit5, step_glyphs};

/// Run the resume path. Caller has already verified the marker file
/// exists at `<home>/vault/.rotation.in-progress`.
pub(crate) async fn run_resume(home: &Path, keystore: &dyn KeyStore) -> Result<()> {
    let g = step_glyphs();
    let vault_dir = home.join("vault");

    // Read marker. Bubbles `exit5` on parse failure.
    let marker = RotationMarker::read(&vault_dir)?;

    // Read current keystore key + verify fingerprint matches marker's
    // new_keyid. Mismatch = refuse with structured error.
    let current_key_bytes = keystore.master_key().await.map_err(|e| {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_resume_keystore_unavailable",
                &format!("could not read current master key during resume: {e}"),
                "verify your OS keychain is responsive",
                None,
            )
        );
        exit5()
    })?;
    let current_keyid = MasterKey::fingerprint_bytes(&current_key_bytes);
    if current_keyid != marker.new_keyid {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_resume_keyid_mismatch",
                &format!(
                    "rotation marker expected new_keyid={} but keystore has {}; \
                     the keystore was modified out-of-band between rotation attempts. \
                     Manual intervention required.",
                    marker.new_keyid, current_keyid
                ),
                "inspect ~/.agentsso/vault/.rotation.in-progress and the OS keychain; \
                 if the rotation never completed, restore the OLD master key in the \
                 keychain manually and remove the marker",
                None,
            )
        );
        return Err(exit5());
    }

    println!(
        "{} resuming rotation  {} marker keyid {} matches keystore",
        g.arrow, g.check, marker.new_keyid
    );

    // ── Phase D (resume): rename remaining .sealed.new → .sealed ──
    let mut renamed = 0u32;
    let mut rename_failures = 0u32;
    let read_dir = match std::fs::read_dir(&vault_dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::error!(error = %e, "could not enumerate vault dir during resume");
            return Err(exit5());
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // We only care about `*.sealed.new` files.
        let Some(stem) = name.strip_suffix(".sealed.new") else { continue };
        if stem.is_empty() {
            continue;
        }
        let live_path = vault_dir.join(format!("{stem}.sealed"));
        if let Err(e) = std::fs::rename(&path, &live_path) {
            if e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            tracing::error!(
                staged = %path.display(),
                live = %live_path.display(),
                error = %e,
                "rename .sealed.new → .sealed failed during resume"
            );
            rename_failures += 1;
        } else {
            renamed += 1;
        }
    }
    if rename_failures > 0 {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_resume_rename_failed",
                &format!(
                    "{rename_failures} rename(s) failed during resume. \
                     Re-run `agentsso rotate-key` to retry."
                ),
                "agentsso rotate-key",
                None,
            )
        );
        return Err(exit5());
    }
    println!("{} renaming staged files  {} {} entries promoted", g.arrow, g.check, renamed);

    // ── Phase E (resume): invalidate agent registry idempotently ──
    //
    // Q4 option B: deleting agent files is naturally idempotent. If
    // a previous run already cleared them, this is a no-op.
    let agents_dir = home.join("agents");
    let agents_invalidated = super::rotation::invalidate_agent_registry(&agents_dir);
    if agents_invalidated > 0 {
        println!(
            "{} invalidating agent tokens  {} {} agent file(s) removed",
            g.arrow, g.check, agents_invalidated
        );
    } else {
        println!(
            "{} invalidating agent tokens  {} no agents to invalidate (already clean)",
            g.arrow, g.check
        );
    }

    // ── Phase F (resume): cleanup + audit ─────────────────────────
    let _ = std::fs::remove_file(RotationMarker::path(&vault_dir));
    super::rotation::emit_master_key_rotated_audit(
        home,
        &marker.old_keyid,
        &marker.new_keyid,
        marker.sealed_count,
        agents_invalidated,
        0, // elapsed_ms unknown on resume
    )
    .await;

    println!(
        "{} rotation resumed and completed  {} {} → {} (resumed; {} entries, {} agents invalidated)",
        g.arrow,
        g.check,
        marker.old_keyid,
        marker.new_keyid,
        marker.sealed_count,
        agents_invalidated
    );
    println!("  next: agentsso start    # bring the daemon back up");
    Ok(())
}
