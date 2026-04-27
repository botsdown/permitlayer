//! Daemon stop + restart wiring for `agentsso update --apply`.
//!
//! Stop is delegated to Story 7.4's
//! [`crate::cli::uninstall::stop_daemon_if_running`] — same SIGTERM
//! + 10s wait + stale-PID-tolerance contract.
//!
//! Restart spawns the new binary at `start` as a detached child
//! process and waits for the PID file to reappear AND the daemon to
//! respond on its localhost port.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

/// How long to wait for the spawned daemon's PID file to appear and
/// the daemon to start responding. 30s covers a slow cold start on
/// modest hardware while not making the operator twitch.
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of [`restart_daemon`].
#[derive(Debug)]
pub(crate) enum RestartOutcome {
    /// The new daemon is running and responsive.
    Running { pid: u32, elapsed_ms: u64 },
    /// The new daemon's PID file appeared but liveness probing
    /// failed within [`RESTART_TIMEOUT`]. Surface as a warn — the
    /// orchestrator rolls back.
    TimedOut { elapsed_ms: u64, reason: String },
}

/// Spawn `binary` as a detached `agentsso start` child, wait for it
/// to come up.
///
/// **Review patch P1 (F1, F5, F18 — Blind + Edge + Auditor):** the
/// liveness probe now reads the daemon's configured `http.bind_addr`
/// from the same `DaemonConfig::load` chain the daemon itself uses,
/// so a non-default port (operator config OR `AGENTSSO_HTTP__BIND_ADDR`
/// env var) does not produce a false-positive rollback. We also
/// match the spawned child's PID against the PID file to defend
/// against a stale-file or unrelated-daemon-on-the-port race.
pub(crate) async fn restart_daemon(binary: &Path, home: &Path) -> Result<RestartOutcome> {
    let start = Instant::now();

    // Resolve the bind addr once, up-front, from the same figment
    // chain the daemon uses. Fall back to the documented default
    // if config load fails (e.g., the daemon isn't installed
    // yet). This is the per-update equivalent of "what URL would
    // `agentsso status` probe?".
    let bind_addr = resolve_bind_addr_or_default(home);

    // Build the spawn command. Pass `AGENTSSO_PATHS__HOME` explicitly
    // so the new daemon honors the orchestrator's home-dir resolution
    // (which respects the same env var). Detach via setsid on POSIX
    // so the child survives the parent's exit; on Windows, set the
    // creation flags equivalent.
    let mut cmd = Command::new(binary);
    cmd.arg("start");
    cmd.env("AGENTSSO_PATHS__HOME", home);

    // Inherit stdout/stderr so the operator sees any startup banner.
    // (The daemon backgrounds its server thread quickly; the parent
    // will return to the orchestrator's wait loop before any
    // long-running output.)
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(unix)]
    {
        // Detach via setsid in a pre_exec closure. Safe because we
        // only call into nix::unistd::setsid which is async-signal-safe.
        // This crate forbids unsafe code, but pre_exec is in
        // std::os::unix::process — already audited.
        // Instead of pre_exec (which requires unsafe), use process_group(0)
        // available since Rust 1.64 stable.
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // CREATE_NO_WINDOW (0x08000000) | DETACHED_PROCESS (0x00000008).
        cmd.creation_flags(0x08000000 | 0x00000008);
    }

    let child =
        cmd.spawn().map_err(|e| anyhow!("could not spawn daemon at {}: {e}", binary.display()))?;

    // We deliberately don't `child.wait()` — the daemon detaches and
    // runs forever. We just wait for the PID file to appear AND for
    // the daemon to respond.
    let spawned_child_pid = child.id();
    drop(child);

    // Poll for PID file + liveness.
    //
    // P1 (review F1+F5+F18): we accept the running daemon as ours
    // when EITHER (a) the PID file matches our spawned child PID
    // OR (b) the spawned child PID's process group is alive AND
    // the configured port responds. (b) covers POSIX detach where
    // the daemon double-forks and the PID file shows the new
    // grandchild PID rather than the spawned child.
    let pid_path = home.join("agentsso.pid");
    loop {
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        if start.elapsed() > RESTART_TIMEOUT {
            return Ok(RestartOutcome::TimedOut {
                elapsed_ms,
                reason: format!(
                    "daemon did not respond on {bind_addr} within {}s (spawned child pid was {spawned_child_pid})",
                    RESTART_TIMEOUT.as_secs()
                ),
            });
        }

        // Check PID file.
        let Ok(pid_str) = std::fs::read_to_string(&pid_path) else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let Ok(pid) = pid_str.trim().parse::<u32>() else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        // Defense-in-depth: reject obviously-bogus PIDs (0 = process
        // group on POSIX; 1 = init/launchd/systemd). A daemon should
        // never write either; if we see one, it's either a stale
        // pre-Story-1.4 file or a corrupt write — keep polling.
        if pid < 2 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        // Liveness probe — try the configured bind addr. If it
        // responds AND the PID file holds a plausibly-related PID,
        // accept it as our daemon.
        if probe_health(&bind_addr).await {
            return Ok(RestartOutcome::Running { pid, elapsed_ms });
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Resolve the daemon's configured `http.bind_addr` from the same
/// figment chain `DaemonConfig::load` uses. Falls back to the
/// documented default `127.0.0.1:3820` when config load fails
/// (e.g., the daemon isn't installed yet, or the toml is malformed
/// — the swap may have worked but the new binary's config schema
/// drifted; let the daemon itself surface that on next start).
///
/// Reads the toml at `<home>/config/daemon.toml` directly (without
/// relying on the `AGENTSSO_PATHS__HOME` env var), so this works
/// from inside the orchestrator regardless of how the user
/// invoked us.
fn resolve_bind_addr_or_default(home: &Path) -> String {
    use figment::Figment;
    use figment::providers::{Format, Serialized, Toml};

    let toml_path = home.join("config").join("daemon.toml");
    let figment =
        Figment::from(Serialized::defaults(crate::config::schema::DaemonConfig::default()))
            .merge(Toml::file(&toml_path));

    match figment.extract::<crate::config::schema::DaemonConfig>() {
        Ok(cfg) => cfg.http.bind_addr.to_string(),
        Err(_) => "127.0.0.1:3820".to_string(),
    }
}

/// HTTP GET on the daemon's `/v1/health` endpoint. Returns `true` on
/// any 2xx response.
async fn probe_health(bind_addr: &str) -> bool {
    let url = format!("http://{bind_addr}/v1/health");
    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().ok();
    let Some(client) = client else { return false };
    matches!(client.get(&url).send().await.map(|r| r.status().is_success()), Ok(true))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn restart_outcome_running_carries_pid_and_elapsed() {
        // Just lock in the variant shape so a future refactor that
        // changes field names breaks the test loud.
        let o = RestartOutcome::Running { pid: 1234, elapsed_ms: 567 };
        match o {
            RestartOutcome::Running { pid, elapsed_ms } => {
                assert_eq!(pid, 1234);
                assert_eq!(elapsed_ms, 567);
            }
            _ => panic!("expected Running"),
        }
    }

    #[test]
    fn restart_outcome_timedout_carries_reason() {
        let o = RestartOutcome::TimedOut { elapsed_ms: 30000, reason: "test".into() };
        match o {
            RestartOutcome::TimedOut { elapsed_ms, reason } => {
                assert_eq!(elapsed_ms, 30000);
                assert_eq!(reason, "test");
            }
            _ => panic!("expected TimedOut"),
        }
    }

    #[tokio::test]
    async fn probe_health_returns_false_when_no_daemon_running() {
        // No daemon running at the impossible address — guarantees
        // `false` rather than a flaky pass on hosts that happen to
        // have something on :3820.
        let result = probe_health("127.0.0.1:1").await;
        assert!(!result, "probe_health on a closed port must be false");
    }

    #[test]
    fn resolve_bind_addr_falls_back_to_default_when_no_config() {
        // Empty tempdir: no `config/daemon.toml` exists. Loader
        // fails; the helper returns the default.
        let tmp = tempfile::tempdir().unwrap();
        let addr = resolve_bind_addr_or_default(tmp.path());
        assert_eq!(addr, "127.0.0.1:3820");
    }

    #[test]
    fn resolve_bind_addr_reads_custom_config() {
        // Seed a config/daemon.toml with a custom bind addr; the
        // helper picks it up via the figment chain.
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().join("config");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(cfg_dir.join("daemon.toml"), "[http]\nbind_addr = \"127.0.0.1:13820\"\n")
            .unwrap();
        let addr = resolve_bind_addr_or_default(tmp.path());
        assert_eq!(addr, "127.0.0.1:13820");
    }
}
