//! `agentsso rotate-key` — master-key rotation for Story 7.6 (FR17).
//!
//! Rotates the 32-byte master key that protects the vault, re-encrypts
//! every sealed credential under the new key, and rebuilds the agent-
//! registry HMAC lookup index. The user keeps every Google connection;
//! no re-OAuth-consent is required.
//!
//! See `_bmad-output/implementation-artifacts/7-6-rotate-key.md` for
//! the spec, the four strategic-question defaults (Q1–Q4), and the
//! cross-story fences inherited from Stories 1.2 / 1.3 / 1.15 / 7.4 /
//! 7.5.
//!
//! # Atomicity sequence (Phases A–F)
//!
//! Reproduced here for the dev's eye-line; full table is in the spec's
//! Dev Notes "Order of operations is the load-bearing invariant":
//!
//! - **A. Re-seal alongside old.** For each credential in the vault,
//!   `unseal_old → seal_new`, write to `<service>.sealed.new`. Old
//!   `.sealed` files untouched. Crash here: orphaned `.sealed.new`,
//!   recoverable to OLD state.
//! - **B. Write `.rotation.in-progress` marker.** Records both keyids,
//!   timestamp, sealed-count. Atomic write + dir fsync.
//! - **C. Keystore swap.** `keystore.set_master_key(new)`. **Pivot.**
//!   Crash before ⇒ recoverable to OLD; crash after ⇒ resume forward
//!   to NEW.
//! - **D. Rename `.sealed.new → .sealed`.** One atomic rename per
//!   service. Idempotent (resume re-runs).
//! - **E. Rebuild agent registry HMACs.** Re-derive every agent's
//!   `lookup_hmac` field under the new master key.
//! - **F. Cleanup.** Delete `.rotation.in-progress`. Emit
//!   `master-key-rotated` audit event.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render;
use crate::design::terminal::ColorSupport;
use permitlayer_keystore::{FallbackMode, KeyStoreKind, KeystoreConfig, default_keystore};

mod resume;
mod rotation;
mod state;

pub(crate) use rotation::run_rotation;
pub(crate) use state::ROTATION_MARKER_FILENAME;

// ── Typed exit-code markers (AC #9) ────────────────────────────────
//
// Mirror Story 7.5's pattern (`UpdateExitCode3/4/5`): typed structs
// (not stringly-typed `.context("rotate_key_exit_code:N")`) so
// `main.rs::rotate_key_to_exit_code` can downcast the chain without
// colliding with operator-visible remediation text.

/// Exit-code 3 marker — resource conflict (daemon running, brew-
/// services managing agentsso). Same semantics as `cli::start`'s
/// exit-3 for a port :3820 conflict and Stories 7.4+7.5's resource-
/// conflict refusals.
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode3;

impl std::fmt::Display for RotateKeyExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: resource conflict")
    }
}

impl std::error::Error for RotateKeyExitCode3 {}

/// Exit-code 4 marker — auth / keystore failure (passphrase adapter
/// rotation refused, set_master_key verify failure, RNG failure).
/// Distinct from 5 so operators can tell "the keystore said no" apart
/// from "the swap succeeded but a later step rolled back."
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode4;

impl std::fmt::Display for RotateKeyExitCode4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: auth or keystore failure")
    }
}

impl std::error::Error for RotateKeyExitCode4 {}

/// Exit-code 5 marker — re-seal / rename / agent-rebuild failure.
/// Reserved as distinct from 4 so operators can triage "did the
/// keystore reject the swap?" vs "did the on-disk rotation roll back?".
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode5;

impl std::fmt::Display for RotateKeyExitCode5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: rotation failure (rolled back where possible)")
    }
}

impl std::error::Error for RotateKeyExitCode5 {}

pub(crate) fn exit3() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode3).context(crate::cli::SilentCliError)
}

pub(crate) fn exit4() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode4).context(crate::cli::SilentCliError)
}

pub(crate) fn exit5() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode5).context(crate::cli::SilentCliError)
}

// ── Glyph helpers (mirror cli::uninstall + cli::update) ────────────

pub(crate) struct StepGlyphs {
    pub arrow: &'static str,
    pub check: &'static str,
}

pub(crate) fn step_glyphs() -> StepGlyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => StepGlyphs { arrow: "->", check: "[ok]" },
        _ => StepGlyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
        },
    }
}

// ── CLI args ───────────────────────────────────────────────────────

/// Arguments for `agentsso rotate-key`.
#[derive(Args, Debug, Default, Clone)]
pub struct RotateKeyArgs {
    /// Skip the interactive confirmation prompt. REQUIRED when
    /// invoked from a non-tty context (CI, scripts, pipes).
    #[arg(long)]
    pub yes: bool,

    /// Treat the call as non-interactive: implies `--yes` is required.
    /// Mirrors `cli::uninstall`'s and `cli::setup`'s posture.
    #[arg(long)]
    pub non_interactive: bool,
}

// ── Entry point ────────────────────────────────────────────────────

/// Run the `rotate-key` subcommand.
pub async fn run(args: RotateKeyArgs) -> Result<()> {
    use anyhow::Context as _;

    // ── Pre-flight 1: brew-services double-bind detection (macOS) ──
    //
    // P19 (Story 7.4 review): pre-flights run BEFORE `init_tracing`
    // so we don't pay the tracing-subscriber setup cost (or risk
    // creating ~/.agentsso/logs/ that step 4 would have to delete)
    // when rotate-key is going to refuse anyway.
    #[cfg(target_os = "macos")]
    if brew_services_managing_agentsso().await {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_managed_externally",
                "agentsso is managed by Homebrew (brew services); rotating the master \
                 key would desync brew's view of the daemon and may leave it pointing at \
                 stale credentials.",
                "brew services stop agentsso && agentsso rotate-key",
                None,
            )
        );
        return Err(exit3());
    }

    // ── Pre-flight 2: daemon-running guard (AC #5) ─────────────────
    //
    // Q1 default A: refuse if daemon up. Rotating while the daemon
    // holds an in-memory copy of the OLD master key opens the same
    // race surface that Story 1.15's HIGH patch closed (AuthLayer /
    // ScopedTokenIssuer desync). Stop first; we don't try to be
    // clever.
    let home = super::agentsso_home()?;
    let daemon_running = crate::lifecycle::pid::PidFile::is_daemon_running(&home)
        .unwrap_or_else(|e| {
            // PID-file-read failure during pre-flight: don't refuse,
            // don't proceed silently. Log + treat as "running" (safer
            // — operator can investigate). The error message goes to
            // stderr via the structured-error block below.
            tracing::warn!(error = %e, "PID-file probe failed; treating daemon as running for safety");
            true
        });
    if daemon_running {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_daemon_running",
                "agentsso daemon is running; rotate-key requires the daemon to be \
                 stopped to avoid in-memory key desync.",
                "agentsso stop && agentsso rotate-key",
                None,
            )
        );
        return Err(exit3());
    }

    // Now safe to init tracing.
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    // ── Pre-flight 3: tty / non-interactive guard (AC #7) ──────────
    let stdout_is_tty = console::Term::stdout().is_term();
    let interactive = !args.non_interactive && stdout_is_tty;
    if !args.yes && !interactive {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_requires_confirmation",
                "rotate-key is destructive (replaces the master key in your OS keychain) \
                 and requires interactive confirmation OR an explicit `--yes` flag.",
                "agentsso rotate-key --yes",
                None,
            )
        );
        return Err(silent_cli_error("non-interactive rotate-key without --yes"));
    }

    // ── Pre-flight 4: keystore-adapter detection (AC #6) ───────────
    //
    // Q2 default A: passphrase adapters cannot be rotated by minting
    // a new key — they rotate by changing the passphrase. Refuse
    // cleanly with a forward-pin to a future `agentsso change-passphrase`
    // command. Do this BEFORE reading the master key so we don't
    // prompt for a passphrase we're about to refuse to use.
    let keystore_config = KeystoreConfig { fallback: FallbackMode::Auto, home: home.clone() };
    let keystore = match default_keystore(&keystore_config) {
        Ok(ks) => ks,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "rotate_key_keystore_unavailable",
                    &format!("keystore initialization failed: {e}"),
                    "verify your OS keychain is available; on Linux this typically \
                     requires libsecret + a running secret-storage daemon (gnome-keyring \
                     / kwallet)",
                    None,
                )
            );
            return Err(exit4());
        }
    };
    if keystore.kind() == KeyStoreKind::Passphrase {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_passphrase_adapter",
                "the passphrase keystore rotates by changing the passphrase, not by \
                 minting a new master key. A dedicated `agentsso change-passphrase` \
                 command will be added in a future story; for now, the passphrase-mode \
                 rotation path is unavailable.",
                "(future) agentsso change-passphrase — not yet implemented",
                None,
            )
        );
        return Err(exit4());
    }

    // ── Pre-flight 5: crash-resume detection (AC #4) ───────────────
    //
    // If a previous rotate-key attempt crashed between Phase C
    // (keystore swap) and Phase F (cleanup), there is a
    // `.rotation.in-progress` marker on disk. Detect it and route to
    // the resume path — DO NOT prompt for confirmation again, and DO
    // NOT mint a new key (the keystore already has the new one).
    let marker_path = home.join("vault").join(ROTATION_MARKER_FILENAME);
    if marker_path.exists() {
        tracing::info!(
            marker = %marker_path.display(),
            "detected in-flight rotation; entering resume path"
        );
        return resume::run_resume(&home, keystore.as_ref()).await;
    }

    // ── Confirm prompt ─────────────────────────────────────────────
    if !args.yes {
        let manifest = build_prompt_manifest(&home);
        println!("{manifest}");

        let join = tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::new().with_prompt("Continue?").default(false).interact()
        })
        .await
        .map_err(|e| anyhow::anyhow!("rotate-key confirm join failed: {e}"))?;
        // `dialoguer::Error` (Ctrl-C, stdin closed) → treat as cancel.
        let confirmed: bool = join.unwrap_or_default();
        if !confirmed {
            println!("rotate-key cancelled");
            return Ok(());
        }
    }

    // ── Run the rotation ───────────────────────────────────────────
    let started = Instant::now();
    run_rotation(&home, keystore.as_ref(), started).await
}

/// Build the manifest block printed before the confirmation prompt
/// (mirrors Story 7.4 `build_prompt_manifest`).
fn build_prompt_manifest(home: &Path) -> String {
    let vault_dir = home.join("vault");
    let mut s = String::new();
    s.push_str("This will rotate the agentsso master encryption key:\n\n");
    s.push_str(&format!(
        "  • Mint a fresh 32-byte master key from your OS RNG\n  \
         • Re-encrypt every credential in {} under the new key\n  \
         • Replace the old master key in your OS keychain (idempotent overwrite)\n  \
         • Rebuild the agent-registry HMAC lookup index in ~/.agentsso/agents/\n  \
         • NOT touch your OAuth refresh tokens — Google connections survive\n\n",
        vault_dir.display()
    ));
    s.push_str(
        "If the rotation is interrupted, re-run `agentsso rotate-key` to \
         finish or roll back automatically.\n",
    );
    s
}

/// macOS-only: probe whether `brew services` is currently managing
/// agentsso. Mirrors `cli::uninstall::brew_services_managing_agentsso`
/// and `cli::update::brew_services_managing_agentsso`.
///
/// **AC #10 fence:** this is the third in-tree caller of the same
/// shell-out. The cli::common refactor that consolidates these three
/// is intentionally deferred per Story 7.6 spec (decision gate AC #10);
/// see deferred-work.md "Cross-story coordination notes from Story 7.6"
/// for the future cleanup ticket.
#[cfg(target_os = "macos")]
async fn brew_services_managing_agentsso() -> bool {
    use std::time::Duration;

    let cmd = tokio::process::Command::new("brew")
        .args(["services", "list", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(Duration::from_secs(30), cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(_)) => return false, // brew not on PATH — proceed.
        Err(_) => return false,     // brew hung past 30s — proceed.
    };
    if !output.status.success() {
        return false;
    }
    crate::lifecycle::autostart::macos::parse_brew_services_active(&output.stdout)
}
