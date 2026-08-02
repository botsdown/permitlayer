//! One-command Homebrew upgrade and privileged daemon reconciliation.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};

const FORMULA: &str = "permitlayer/tap/agentsso";

#[derive(Args, Debug, Default, Clone)]
pub struct UpgradeArgs {
    /// Show the commands that would run without changing the installation.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UpgradeJournal {
    schema_version: u16,
    phase: String,
    formula: String,
    cli_version_before: String,
    activated_binary: Option<String>,
    #[serde(default)]
    previous_helper: Option<String>,
}

pub async fn run(args: UpgradeArgs) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        bail!("`agentsso upgrade` currently supports Homebrew installations on macOS only");
    }
    #[cfg(target_os = "macos")]
    run_macos(args).await.context("resume with: `agentsso upgrade`")
}

#[cfg(target_os = "macos")]
async fn run_macos(args: UpgradeArgs) -> Result<()> {
    #[cfg(debug_assertions)]
    let dry_run =
        args.dry_run || std::env::var("AGENTSSO_UPGRADE_DRY_RUN").ok().as_deref() == Some("1");
    #[cfg(not(debug_assertions))]
    let dry_run = args.dry_run;
    if dry_run {
        let brew = locate_brew().unwrap_or_else(|_| PathBuf::from("brew"));
        println!("→ upgrading {FORMULA} with {}", brew.display());
        println!("  would run: {} upgrade {FORMULA}", brew.display());
        println!("  would run the newly installed binary: agentsso setup --upgrade");
        println!("  would verify: launchd, control socket, and exact daemon version");
        return Ok(());
    }
    let brew = locate_brew()?;
    println!("→ upgrading {FORMULA} with {}", brew.display());
    let journal = journal_path()?;
    let _upgrade_lock = acquire_upgrade_lock(&journal)?;
    let mut progress = load_journal(&journal)?.unwrap_or_else(|| UpgradeJournal {
        schema_version: 1,
        phase: "brew-upgrade".to_owned(),
        formula: FORMULA.to_owned(),
        cli_version_before: env!("CARGO_PKG_VERSION").to_owned(),
        activated_binary: None,
        previous_helper: current_helper_target(),
    });
    if progress.schema_version != 1 || progress.formula != FORMULA {
        bail!("the existing upgrade journal is incompatible; inspect {}", journal.display());
    }
    persist_journal(&journal, &progress)?;

    if progress.phase == "brew-upgrade" {
        run_inherited(Command::new(&brew).arg("upgrade").arg(FORMULA), "Homebrew upgrade")?;
        let installed = homebrew_binary(&brew)?;
        progress.activated_binary = Some(installed.display().to_string());
        progress.phase = "activate-daemon".to_owned();
        persist_journal(&journal, &progress)?;
    }
    let installed = progress
        .activated_binary
        .as_deref()
        .map(PathBuf::from)
        .context("upgrade journal omitted the activated Homebrew binary")?;
    let installed_version = verify_agentsso_binary(&installed)?;

    let converge = async {
        if progress.phase == "activate-daemon" {
            println!("→ activating the Homebrew binary as the system service");
            run_privileged(&installed, &["setup", "--upgrade"], "PermitLayer service activation")?;
            progress.phase = "reconcile-enrollments".to_owned();
            persist_journal(&journal, &progress)?;
        }
        if progress.phase == "reconcile-enrollments" {
            println!("→ reconciling previously consented local enrollments");
            run_privileged(
                &installed,
                &["onboard", "reconcile"],
                "PermitLayer enrollment reconciliation",
            )?;
            progress.phase = "verify".to_owned();
            persist_journal(&journal, &progress)?;
        }
        if progress.phase != "verify" {
            bail!("upgrade journal contains unknown phase '{}'", progress.phase);
        }
        println!("→ verifying the converged service");
        run_inherited(
            Command::new(&installed).arg("service").arg("status"),
            "PermitLayer service verification",
        )?;
        verify_daemon_version(&installed_version).await
    }
    .await;
    if let Err(error) = converge {
        let rollback = rollback_previous_helper(&progress);
        return match rollback {
            Ok(true) => {
                Err(error).context("activation failed; restored the previous daemon helper")
            }
            Ok(false) => Err(error).context(
                "activation failed and no previous helper was available for automatic rollback",
            ),
            Err(rollback_error) => Err(error).context(format!(
                "activation failed; automatic rollback also failed: {rollback_error}"
            )),
        };
    }

    if let Err(error) = std::fs::remove_file(&journal)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("warning: upgrade succeeded but its journal could not be removed: {error}");
    }
    println!("✓ agentsso upgrade complete");
    Ok(())
}

#[cfg(target_os = "macos")]
const HELPER_LINK: &str = "/Library/PrivilegedHelperTools/agentsso";

#[cfg(target_os = "macos")]
fn current_helper_target() -> Option<String> {
    let link = Path::new(HELPER_LINK);
    let target = std::fs::read_link(link).ok()?;
    let resolved = if target.is_absolute() { target } else { link.parent()?.join(target) };
    resolved.is_file().then(|| resolved.display().to_string())
}

#[cfg(target_os = "macos")]
fn run_privileged(binary: &Path, args: &[&str], operation: &str) -> Result<()> {
    let mut command = Command::new("/usr/bin/sudo");
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        command.arg("-n");
    }
    command.arg(binary).args(args);
    run_inherited(&mut command, operation).with_context(|| {
        "administrator authorization is required; authenticate with sudo first or configure sudo -n for unattended upgrades"
    })
}

#[cfg(target_os = "macos")]
fn rollback_previous_helper(journal: &UpgradeJournal) -> Result<bool> {
    let Some(previous) = journal.previous_helper.as_deref() else { return Ok(false) };
    let binary = Path::new(previous);
    if !binary.is_file() {
        return Ok(false);
    }
    eprintln!("→ restoring previous daemon helper from {}", binary.display());
    run_privileged(binary, &["setup", "--upgrade"], "PermitLayer rollback")?;
    Ok(true)
}

#[cfg(target_os = "macos")]
fn locate_brew() -> Result<PathBuf> {
    for candidate in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!(
        "Homebrew was not found; install/upgrade agentsso through the same package source, then run `sudo agentsso setup --upgrade`"
    )
}

#[cfg(target_os = "macos")]
fn homebrew_binary(brew: &Path) -> Result<PathBuf> {
    let output = Command::new(brew)
        .arg("--prefix")
        .arg(FORMULA)
        .output()
        .context("failed to locate the upgraded Homebrew formula")?;
    if !output.status.success() {
        bail!("Homebrew upgraded agentsso but did not report its install prefix");
    }
    let prefix =
        String::from_utf8(output.stdout).context("Homebrew returned a non-UTF-8 prefix")?;
    let binary = PathBuf::from(prefix.trim()).join("bin/agentsso");
    if !binary.is_file() {
        bail!("the upgraded Homebrew binary is missing at {}", binary.display());
    }
    Ok(binary)
}

#[cfg(target_os = "macos")]
fn verify_agentsso_binary(binary: &Path) -> Result<String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .with_context(|| format!("cannot execute {}", binary.display()))?;
    if !output.status.success() {
        bail!("the upgraded binary failed its --version check");
    }
    let version = String::from_utf8_lossy(&output.stdout);
    if !version.trim_start().starts_with("agentsso ") {
        bail!("the Homebrew formula did not install an agentsso binary");
    }
    let version = version.trim().trim_start_matches("agentsso ").to_owned();
    println!("  ✓ selected {} (agentsso {version})", binary.display());
    Ok(version)
}

#[cfg(target_os = "macos")]
async fn verify_daemon_version(expected: &str) -> Result<()> {
    let home = crate::cli::agentsso_home()?;
    let handle = crate::cli::connect_uds::require_daemon_running(&home)
        .await
        .context("the upgraded daemon control plane is not reachable")?;
    let (status, body) = crate::cli::kill::http_get_with_status_via(
        &handle.endpoint,
        "/v1/control/whoami",
        handle.control_token.as_deref(),
    )
    .await?;
    if !(200..300).contains(&status) {
        bail!("the upgraded daemon rejected its version probe with HTTP {status}");
    }
    let value: serde_json::Value =
        serde_json::from_str(&body).context("invalid daemon identity")?;
    let actual = value["version"].as_str().context("daemon identity omitted its version")?;
    if actual != expected {
        bail!("version drift remains after activation: CLI {expected}, daemon {actual}");
    }
    println!("  ✓ daemon version {actual} matches the upgraded CLI");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_inherited(command: &mut Command, operation: &str) -> Result<()> {
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to start {operation}"))?;
    if !status.success() {
        bail!("{operation} failed with {status}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn journal_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot resolve the operator home directory")?;
    Ok(home.join("Library/Caches/dev.permitlayer/upgrade-journal.json"))
}

#[cfg(target_os = "macos")]
fn acquire_upgrade_lock(journal: &Path) -> Result<std::fs::File> {
    let parent = journal.parent().context("upgrade journal has no parent")?;
    std::fs::create_dir_all(parent)?;
    let path = parent.join("upgrade.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    file.try_lock().map_err(|error| {
        anyhow::anyhow!("another agentsso upgrade is already running ({}): {error}", path.display())
    })?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn persist_journal(path: &Path, journal: &UpgradeJournal) -> Result<()> {
    let parent = path.parent().context("upgrade journal has no parent")?;
    std::fs::create_dir_all(parent).context("create upgrade journal directory")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("create upgrade journal temporary file")?;
    use std::io::Write as _;
    temporary.write_all(&serde_json::to_vec_pretty(journal)?).context("write upgrade journal")?;
    temporary.as_file().sync_all().context("sync upgrade journal")?;
    temporary.persist(path).map_err(|error| error.error).context("install upgrade journal")?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_journal(path: &Path) -> Result<Option<UpgradeJournal>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read upgrade journal"),
    };
    serde_json::from_slice(&bytes).map(Some).context("invalid upgrade journal")
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn upgrade_journal_round_trips_and_accepts_pre_rollback_records() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("upgrade.json");
        let journal = UpgradeJournal {
            schema_version: 1,
            phase: "verify".to_owned(),
            formula: FORMULA.to_owned(),
            cli_version_before: "1.4.1".to_owned(),
            activated_binary: Some("/tmp/agentsso".to_owned()),
            previous_helper: Some("/tmp/agentsso-1.4.1".to_owned()),
        };
        persist_journal(&path, &journal)?;
        let loaded = load_journal(&path)?.context("journal missing after persist")?;
        assert_eq!(loaded.phase, "verify");
        assert_eq!(loaded.previous_helper.as_deref(), Some("/tmp/agentsso-1.4.1"));

        std::fs::write(
            &path,
            r#"{"schema_version":1,"phase":"activate-daemon","formula":"permitlayer/tap/agentsso","cli_version_before":"1.4.1","activated_binary":"/tmp/agentsso"}"#,
        )?;
        let loaded = load_journal(&path)?.context("legacy journal was not loaded")?;
        assert!(loaded.previous_helper.is_none());
        Ok(())
    }
}
