//! Resumable, secretless local agent-runtime onboarding.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use permitlayer_core::store::{ConnectionRecord, ConnectionStatus, ConnectionTier};
use serde::{Deserialize, Serialize};

use crate::cli::connect_uds::{self, ControlOutcome};

#[derive(Args, Debug)]
pub struct OnboardArgs {
    #[command(subcommand)]
    pub command: OnboardCommand,
}

#[derive(Subcommand, Debug)]
pub enum OnboardCommand {
    /// Configure Hermes with UID-authenticated PermitLayer stdio bridges.
    Hermes(HermesArgs),
    /// Reconcile previously completed or interrupted local enrollments.
    #[command(hide = true)]
    Reconcile,
}

#[derive(Args, Debug, Clone)]
pub struct HermesArgs {
    /// macOS account that runs Hermes.
    #[arg(long)]
    pub user: String,
    /// PermitLayer agent to create or adopt.
    #[arg(long)]
    pub agent: Option<String>,
    /// Gmail connection name or ID. Omit to auto-select when unambiguous.
    #[arg(long)]
    pub gmail: Option<String>,
    /// Calendar connection name or ID. Omit to auto-select when unambiguous.
    #[arg(long)]
    pub calendar: Option<String>,
    /// Drive connection name or ID. Omit to auto-select when unambiguous.
    #[arg(long)]
    pub drive: Option<String>,
    /// Replace a different existing local consent set after explicit review.
    #[arg(long)]
    pub replace_local_access: bool,
    #[arg(long, hide = true)]
    pub root_phase: bool,
    #[arg(long, hide = true)]
    pub target_phase: bool,
    #[arg(long = "selected-service", hide = true)]
    pub selected_services: Vec<String>,
    #[arg(long = "bridge-command", hide = true)]
    pub bridge_command: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OnboardingJournal {
    schema_version: u16,
    user: String,
    uid: u32,
    agent: String,
    phase: String,
    services: Vec<EnrolledService>,
    capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EnrolledService {
    service: String,
    connection_id: String,
    connection_name: String,
}

struct SelectedConnection {
    service: &'static str,
    record: ConnectionRecord,
}

pub async fn run(args: OnboardArgs) -> Result<()> {
    match args.command {
        OnboardCommand::Hermes(args) => run_hermes(args).await,
        OnboardCommand::Reconcile => reconcile_enrollments().await,
    }
}

async fn run_hermes(args: HermesArgs) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        bail!("secretless Hermes onboarding is currently supported on macOS only");
    }
    #[cfg(target_os = "macos")]
    {
        if args.target_phase {
            return configure_target_hermes(&args);
        }
        if !nix::unistd::Uid::effective().is_root() {
            preflight_user(&args.user)?;
            let home = crate::cli::agentsso_home()?;
            connect_uds::require_daemon_running(&home)
                .await
                .context("onboard hermes: daemon not reachable")?;
            let resume = resume_command(&args);
            return elevate_once(&args).with_context(|| format!("resume with: `{resume}`"));
        }
        let resume = resume_command(&args);
        root_onboard(args).await.with_context(|| format!("resume with: `{resume}`"))
    }
}

#[cfg(target_os = "macos")]
fn preflight_user(username: &str) -> Result<nix::unistd::User> {
    let user = nix::unistd::User::from_name(username)
        .context("resolve Hermes macOS account")?
        .with_context(|| format!("macOS user '{username}' does not exist"))?;
    if user.uid.as_raw() < 501 {
        bail!("Hermes must run as a non-system macOS account");
    }
    Ok(user)
}

#[cfg(target_os = "macos")]
fn elevate_once(args: &HermesArgs) -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!(
            "onboarding needs one administrator authorization; rerun with `sudo agentsso onboard hermes --user {}`",
            args.user
        );
    }
    let binary = std::env::current_exe().context("resolve the running agentsso executable")?;
    println!("→ onboarding needs one administrator authorization");
    let mut command = Command::new("/usr/bin/sudo");
    command.arg(&binary).arg("onboard").arg("hermes").arg("--user").arg(&args.user);
    copy_operator_args(&mut command, args);
    command.arg("--root-phase");
    run_inherited(&mut command, "privileged Hermes onboarding")
}

#[cfg(target_os = "macos")]
async fn root_onboard(args: HermesArgs) -> Result<()> {
    let target = preflight_user(&args.user)?;
    let home = crate::cli::agentsso_home()?;
    let _onboarding_lock = acquire_file_lock(
        &home.join("onboarding").join(format!("hermes-{}.lock", target.uid.as_raw())),
        "another Hermes onboarding is already running for this user",
    )?;
    let handle = connect_uds::require_daemon_running(&home)
        .await
        .context("onboard hermes: daemon not reachable")?;
    let agent = args.agent.clone().unwrap_or_else(|| default_agent_name(&target.name));
    permitlayer_core::agent::validate_agent_name(&agent)
        .map_err(|_| anyhow::anyhow!("derived agent name '{agent}' is invalid; pass --agent"))?;

    let prior = load_journal(&home, target.uid.as_raw())?;
    if let Some(prior) = &prior
        && (prior.user != target.name || prior.agent != agent)
    {
        bail!(
            "an existing enrollment journal for uid {} belongs to user '{}' and agent '{}'; review {} before changing identity",
            target.uid,
            prior.user,
            prior.agent,
            journal_path(&home, target.uid.as_raw()).display()
        );
    }
    let mut selection_args = args.clone();
    if let Some(prior) = &prior {
        apply_recorded_connections(&mut selection_args, prior)?;
    }
    let selected = select_connections(&handle, &selection_args).await?;
    if selected.is_empty() {
        bail!("no active Gmail, Calendar, or Drive connections are available to onboard");
    }
    let mut capabilities = prior
        .as_ref()
        .map(|journal| journal.capabilities.clone())
        .unwrap_or_else(|| capabilities_for_connections(&selected));
    capabilities.sort();
    capabilities.dedup();
    let mut journal = OnboardingJournal {
        schema_version: 1,
        user: target.name.clone(),
        uid: target.uid.as_raw(),
        agent: agent.clone(),
        phase: "agent-and-bindings".to_owned(),
        services: selected
            .iter()
            .map(|selection| EnrolledService {
                service: selection.service.to_owned(),
                connection_id: selection.record.id.to_string(),
                connection_name: selection.record.name.clone(),
            })
            .collect(),
        capabilities: capabilities.clone(),
    };
    write_journal(&home, target.uid.as_raw(), &journal)?;
    ensure_agent(&handle, &agent).await?;
    ensure_bindings(&handle, &agent, &selected).await?;

    let selectors: Vec<String> =
        selected.iter().map(|selection| selection.service.to_owned()).collect();
    let grant = connect_uds::GrantLocalAccessRequest {
        agent: &agent,
        user: &target.name,
        capabilities: &capabilities,
        connections: &selectors,
        profile: Some("hermes-standard@1"),
        replace: args.replace_local_access,
    };
    match connect_uds::post_grant_local_access(&handle, &grant).await? {
        ControlOutcome::Ok(_) => {}
        ControlOutcome::Err { status_code, body } => {
            bail!("local consent failed (HTTP {status_code}, {}): {}", body.code, body.message)
        }
        ControlOutcome::ParseFailure { status_code, .. } => {
            bail!("local consent returned an invalid response (HTTP {status_code})")
        }
    }

    journal.phase = "target-config".to_owned();
    write_journal(&home, target.uid.as_raw(), &journal)?;
    let bridge = stable_cli_path()?;
    let mut target_command = Command::new("/usr/bin/sudo");
    target_command
        .arg("-u")
        .arg(&target.name)
        .arg("-H")
        .arg(&bridge)
        .arg("onboard")
        .arg("hermes")
        .arg("--user")
        .arg(&target.name)
        .arg("--target-phase")
        .arg("--bridge-command")
        .arg(&bridge);
    for selection in &selected {
        target_command.arg("--selected-service").arg(selection.service);
    }
    run_inherited(&mut target_command, "Hermes user configuration")?;
    journal.phase = "complete".to_owned();
    write_journal(&home, target.uid.as_raw(), &journal)?;
    println!("✓ Hermes onboarding complete for '{}' as agent '{}'", target.name, agent);
    println!("  run /reload-mcp in Hermes to load the PermitLayer bridges");
    Ok(())
}

#[cfg(target_os = "macos")]
fn capabilities_for_connections(selected: &[SelectedConnection]) -> Vec<String> {
    let mut capabilities = Vec::new();
    for selection in selected {
        capabilities.push(format!("mcp-{}", selection.service));
        if selection.service == "drive" {
            capabilities.push("drive-download".to_owned());
            if matches!(
                selection.record.tier,
                ConnectionTier::ReadWrite | ConnectionTier::FullControl
            ) {
                capabilities.push("drive-upload".to_owned());
            }
            if selection.record.tier == ConnectionTier::FullControl {
                capabilities.push("drive-replace".to_owned());
            }
        }
    }
    capabilities
}

#[cfg(target_os = "macos")]
fn apply_recorded_connections(args: &mut HermesArgs, journal: &OnboardingJournal) -> Result<()> {
    let recorded_services: std::collections::HashSet<&str> =
        journal.services.iter().map(|service| service.service.as_str()).collect();
    for (service, requested) in [
        ("gmail", args.gmail.as_deref()),
        ("calendar", args.calendar.as_deref()),
        ("drive", args.drive.as_deref()),
    ] {
        if requested.is_some() && !recorded_services.contains(service) {
            bail!(
                "the existing enrollment does not include {service}; refusing to expand local access during reconciliation"
            );
        }
    }
    if !recorded_services.contains("gmail") {
        args.gmail = None;
    }
    if !recorded_services.contains("calendar") {
        args.calendar = None;
    }
    if !recorded_services.contains("drive") {
        args.drive = None;
    }
    for enrolled in &journal.services {
        let slot = match enrolled.service.as_str() {
            "gmail" => &mut args.gmail,
            "calendar" => &mut args.calendar,
            "drive" => &mut args.drive,
            service => bail!("enrollment journal contains unsupported service '{service}'"),
        };
        if let Some(requested) = slot.as_deref()
            && requested != enrolled.connection_id
            && requested != enrolled.connection_name
        {
            bail!(
                "enrollment is pinned to {} connection '{}' ({}); refusing requested selector '{}'",
                enrolled.service,
                enrolled.connection_name,
                enrolled.connection_id,
                requested
            );
        }
        *slot = Some(enrolled.connection_id.clone());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) async fn reconcile_enrollments() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("enrollment reconciliation must run as root");
    }
    let home = crate::cli::agentsso_home()?;
    let dir = home.join("onboarding");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("read enrollment directory"),
    };
    let mut journals = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let is_hermes_record = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hermes-") && name.ends_with(".json"));
        if !is_hermes_record {
            continue;
        }
        let journal: OnboardingJournal = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("invalid enrollment record {}", path.display()))?;
        if journal.schema_version != 1 {
            bail!("unsupported enrollment record version in {}", path.display());
        }
        journals.push(journal);
    }
    journals.sort_by_key(|journal| journal.uid);
    for journal in journals {
        let mut args = HermesArgs {
            user: journal.user.clone(),
            agent: Some(journal.agent.clone()),
            gmail: None,
            calendar: None,
            drive: None,
            replace_local_access: false,
            root_phase: true,
            target_phase: false,
            selected_services: Vec::new(),
            bridge_command: None,
        };
        apply_recorded_connections(&mut args, &journal)?;
        root_onboard(args).await?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn reconcile_enrollments() -> Result<()> {
    bail!("enrollment reconciliation is currently supported on macOS only")
}

#[cfg(target_os = "macos")]
async fn select_connections(
    handle: &connect_uds::ConnectControlHandle,
    args: &HermesArgs,
) -> Result<Vec<SelectedConnection>> {
    let records = match connect_uds::get_connection_records(handle).await? {
        ControlOutcome::Ok(response) => response.connections,
        ControlOutcome::Err { status_code, body } => {
            bail!("connection list failed (HTTP {status_code}, {}): {}", body.code, body.message)
        }
        ControlOutcome::ParseFailure { status_code, .. } => {
            bail!("connection list returned an invalid response (HTTP {status_code})")
        }
    };
    let mut selected = Vec::new();
    for (service, connector, requested) in [
        ("gmail", "google-gmail", args.gmail.as_deref()),
        ("calendar", "google-calendar", args.calendar.as_deref()),
        ("drive", "google-drive", args.drive.as_deref()),
    ] {
        let candidates: Vec<_> = records
            .iter()
            .filter(|record| {
                record.connector_id == connector && record.status == ConnectionStatus::Active
            })
            .collect();
        let record = if let Some(selector) = requested {
            candidates
                .iter()
                .find(|record| record.name == selector || record.id.to_string() == selector)
                .copied()
                .with_context(|| {
                    format!("active {service} connection '{selector}' was not found")
                })?
        } else {
            match candidates.as_slice() {
                [] => continue,
                [only] => *only,
                many => {
                    let names = many.iter().map(|record| record.name.as_str()).collect::<Vec<_>>();
                    bail!(
                        "multiple active {service} connections exist ({}); select one with --{service} <name>",
                        names.join(", ")
                    );
                }
            }
        };
        selected.push(SelectedConnection { service, record: record.clone() });
    }
    Ok(selected)
}

#[cfg(target_os = "macos")]
async fn ensure_agent(handle: &connect_uds::ConnectControlHandle, agent: &str) -> Result<()> {
    let (status, body) = crate::cli::kill::http_get_with_status_via(
        &handle.endpoint,
        "/v1/control/agent/list",
        handle.control_token.as_deref(),
    )
    .await?;
    if !(200..300).contains(&status) {
        bail!("agent list failed with HTTP {status}");
    }
    let value: serde_json::Value = serde_json::from_str(&body).context("invalid agent list")?;
    if let Some(existing) = value["agents"]
        .as_array()
        .and_then(|agents| agents.iter().find(|entry| entry["name"] == agent))
    {
        if existing["local_only"] == true {
            return Ok(());
        }
        bail!(
            "agent '{agent}' already exists as a bearer-capable identity; choose a different \
             --agent name so Hermes can use a local-only identity"
        );
    }
    let request = serde_json::json!({
        "name": agent,
        "policy_name": "gmail-read-only",
        "local_only": true
    })
    .to_string();
    let response = crate::cli::kill::http_post_json_via(
        &handle.endpoint,
        "/v1/control/agent/register",
        &request,
        handle.control_token.as_deref(),
    )
    .await?;
    let value: serde_json::Value =
        serde_json::from_str(&response).context("invalid agent register response")?;
    if value["status"] != "ok" {
        bail!(
            "agent registration failed: {}",
            value["message"].as_str().unwrap_or("unknown error")
        );
    }
    // Local-only registration returns no bearer and is usable only through
    // the kernel-UID-authenticated Unix-socket bridge.
    Ok(())
}

#[cfg(target_os = "macos")]
async fn ensure_bindings(
    handle: &connect_uds::ConnectControlHandle,
    agent: &str,
    selected: &[SelectedConnection],
) -> Result<()> {
    let existing = match connect_uds::get_agent_bindings(handle, agent).await? {
        ControlOutcome::Ok(response) => response.bindings,
        ControlOutcome::Err { status_code, body } => {
            bail!("agent bindings failed (HTTP {status_code}, {}): {}", body.code, body.message)
        }
        ControlOutcome::ParseFailure { status_code, .. } => {
            bail!("agent bindings returned an invalid response (HTTP {status_code})")
        }
    };
    for selection in selected {
        let id = selection.record.id.to_string();
        let tier = tier_name(selection.record.tier);
        if let Some(binding) = existing.iter().find(|binding| binding.connection_id == id) {
            if binding.alias.as_deref() != Some(selection.service) || binding.tier != tier {
                bail!(
                    "agent '{agent}' already has connection '{}' bound differently; review `agentsso agent bindings {agent}` before changing it",
                    selection.record.name
                );
            }
            continue;
        }
        let request = connect_uds::BindRequest {
            agent,
            connection_id: &id,
            tier,
            policy: None,
            alias: Some(selection.service),
        };
        match connect_uds::post_bind(handle, &request).await? {
            ControlOutcome::Ok(_) => {}
            ControlOutcome::Err { status_code, body } => bail!(
                "binding {} failed (HTTP {status_code}, {}): {}",
                selection.service,
                body.code,
                body.message
            ),
            ControlOutcome::ParseFailure { status_code, .. } => {
                bail!("binding returned an invalid response (HTTP {status_code})")
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_target_hermes(args: &HermesArgs) -> Result<()> {
    let current = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("cannot resolve current target account")?;
    if current.name != args.user || current.uid.as_raw() < 501 {
        bail!("target configuration must run as the enrolled Hermes account");
    }
    let bridge = args.bridge_command.as_deref().context("missing managed bridge command")?;
    if !bridge.is_file() {
        bail!("managed bridge command is missing at {}", bridge.display());
    }
    let config_dir = current.dir.join(".hermes");
    std::fs::create_dir_all(&config_dir).context("create ~/.hermes")?;
    let _config_lock = acquire_file_lock(
        &config_dir.join(".permitlayer-onboard.lock"),
        "another PermitLayer process is updating the Hermes configuration",
    )?;
    let config = config_dir.join("config.yaml");
    let original_exists = config.exists();
    let original = match std::fs::read_to_string(&config) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("read Hermes config"),
    };
    let hermes = find_hermes_binary(&current.dir);
    if let Some(binary) = &hermes {
        let status = Command::new(binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .context("probe Hermes version")?;
        if !status.success() {
            bail!("the installed Hermes binary failed its version probe");
        }
    }
    let merged = merge_hermes_config(&original, &args.selected_services, bridge)?;
    if merged == original {
        return Ok(());
    }
    let backup = config.with_extension("yaml.permitlayer.bak");
    if config.exists() {
        std::fs::copy(&config, &backup).context("back up Hermes config")?;
    }
    atomic_user_write(&config, merged.as_bytes())?;
    if let Some(hermes) = hermes {
        let status = Command::new(hermes)
            .arg("mcp")
            .arg("list")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .context("validate Hermes MCP configuration")?;
        if !status.success() {
            if original_exists {
                atomic_user_write(&config, original.as_bytes())
                    .context("restore the prior Hermes config")?;
            } else if let Err(error) = std::fs::remove_file(&config)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error).context("remove rejected first-run Hermes config");
            }
            bail!("Hermes rejected its updated MCP configuration; the prior config was restored");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn merge_hermes_config(original: &str, services: &[String], bridge: &Path) -> Result<String> {
    if original.contains('\t') {
        bail!("Hermes config contains tab indentation; refusing an unsafe automatic merge");
    }
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    if lines.iter().any(|line| {
        let trimmed = line.trim_start();
        !line.starts_with(' ')
            && !line.starts_with('\t')
            && (trimmed.starts_with("mcp_servers:") && trimmed != "mcp_servers:"
                || trimmed.starts_with("\"mcp_servers\":")
                || trimmed.starts_with("'mcp_servers':"))
    }) {
        bail!(
            "Hermes config uses an unsupported mcp_servers YAML layout; normalize it to a top-level block mapping before onboarding"
        );
    }
    let roots: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim_end() == "mcp_servers:" && !line.starts_with(' '))
        .map(|(index, _)| index)
        .collect();
    if roots.len() > 1 {
        bail!("Hermes config contains multiple top-level mcp_servers mappings");
    }
    let root = if let Some(root) = roots.first().copied() {
        root
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
            lines.push(String::new());
        }
        lines.push("mcp_servers:".to_owned());
        lines.len() - 1
    };
    let mut end = root + 1;
    while end < lines.len() {
        let line = &lines[end];
        if !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        end += 1;
    }
    for service in ["gmail", "calendar", "drive"] {
        let key = format!("  permitlayer_{service}:");
        let mut cursor = root + 1;
        while cursor < end {
            if lines[cursor].trim_end() == key {
                let mut entry_end = cursor + 1;
                while entry_end < end
                    && (lines[entry_end].trim().is_empty() || lines[entry_end].starts_with("    "))
                {
                    entry_end += 1;
                }
                let existing = lines[cursor..entry_end].join("\n");
                if !existing.contains("# managed-by: permitlayer/hermes-stdio-v1") {
                    bail!(
                        "Hermes already has an unrelated MCP server named permitlayer_{service}; refusing to overwrite it"
                    );
                }
                lines.drain(cursor..entry_end);
                end -= entry_end - cursor;
                continue;
            }
            cursor += 1;
        }
    }
    let command = serde_json::to_string(&bridge.to_string_lossy().as_ref())?;
    let mut managed = Vec::new();
    let mut ordered = services.to_vec();
    ordered.sort();
    ordered.dedup();
    for service in ordered {
        if !matches!(service.as_str(), "gmail" | "calendar" | "drive") {
            bail!("unsupported managed Hermes service '{service}'");
        }
        managed.push(format!("  permitlayer_{service}:"));
        managed.push("    # managed-by: permitlayer/hermes-stdio-v1".to_owned());
        managed.push(format!("    command: {command}"));
        managed.push(format!("    args: [\"mcp\", \"bridge\", \"--service\", \"{service}\"]"));
        managed.push("    enabled: true".to_owned());
    }
    lines.splice(end..end, managed);
    let mut result = lines.join("\n");
    result.push('\n');
    Ok(result)
}

#[cfg(target_os = "macos")]
fn atomic_user_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let parent = path.parent().context("Hermes config has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_operator_args(command: &mut Command, args: &HermesArgs) {
    if let Some(agent) = &args.agent {
        command.arg("--agent").arg(agent);
    }
    for (flag, value) in [
        ("--gmail", args.gmail.as_ref()),
        ("--calendar", args.calendar.as_ref()),
        ("--drive", args.drive.as_ref()),
    ] {
        if let Some(value) = value {
            command.arg(flag).arg(value);
        }
    }
    if args.replace_local_access {
        command.arg("--replace-local-access");
    }
}

#[cfg(target_os = "macos")]
fn resume_command(args: &HermesArgs) -> String {
    let mut parts = vec![
        "agentsso".to_owned(),
        "onboard".to_owned(),
        "hermes".to_owned(),
        "--user".to_owned(),
        shell_quote(&args.user),
    ];
    for (flag, value) in [
        ("--agent", args.agent.as_ref()),
        ("--gmail", args.gmail.as_ref()),
        ("--calendar", args.calendar.as_ref()),
        ("--drive", args.drive.as_ref()),
    ] {
        if let Some(value) = value {
            parts.push(flag.to_owned());
            parts.push(shell_quote(value));
        }
    }
    if args.replace_local_access {
        parts.push("--replace-local-access".to_owned());
    }
    parts.join(" ")
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    if value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

#[cfg(target_os = "macos")]
fn tier_name(tier: ConnectionTier) -> &'static str {
    match tier {
        ConnectionTier::Read => "read",
        ConnectionTier::ReadWrite => "read-write",
        ConnectionTier::FullControl => "full-control",
    }
}

#[cfg(target_os = "macos")]
fn default_agent_name(username: &str) -> String {
    let normalized: String =
        username
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() { character.to_ascii_lowercase() } else { '-' }
            })
            .collect();
    format!("hermes-{}", normalized.trim_matches('-'))
}

#[cfg(target_os = "macos")]
fn stable_cli_path() -> Result<PathBuf> {
    let current = std::env::current_exe().context("resolve agentsso executable")?;
    let canonical_current = std::fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
    for candidate in ["/opt/homebrew/bin/agentsso", "/usr/local/bin/agentsso"] {
        let path = PathBuf::from(candidate);
        if path.is_file()
            && std::fs::canonicalize(&path).is_ok_and(|resolved| resolved == canonical_current)
        {
            return Ok(path);
        }
    }
    Ok(current)
}

#[cfg(target_os = "macos")]
fn find_hermes_binary(home: &Path) -> Option<PathBuf> {
    [
        home.join(".local/bin/hermes"),
        home.join(".hermes/bin/hermes"),
        PathBuf::from("/usr/local/bin/hermes"),
        PathBuf::from("/opt/homebrew/bin/hermes"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
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
fn acquire_file_lock(path: &Path, busy_message: &str) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let parent = path.parent().context("lock file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| anyhow::anyhow!("{busy_message}: {error}"))?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn journal_path(home: &Path, uid: u32) -> PathBuf {
    home.join("onboarding").join(format!("hermes-{uid}.json"))
}

#[cfg(target_os = "macos")]
fn write_journal(home: &Path, uid: u32, journal: &OnboardingJournal) -> Result<()> {
    use std::io::Write as _;
    let path = journal_path(home, uid);
    let parent = path.parent().context("onboarding journal has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&serde_json::to_vec_pretty(journal)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_journal(home: &Path, uid: u32) -> Result<Option<OnboardingJournal>> {
    let path = journal_path(home, uid);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read onboarding journal"),
    };
    let journal: OnboardingJournal =
        serde_json::from_slice(&bytes).context("invalid onboarding journal")?;
    if journal.schema_version != 1 || journal.uid != uid {
        bail!("onboarding journal has an unsupported version or mismatched UID");
    }
    Ok(Some(journal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_merge_preserves_unrelated_configuration() -> anyhow::Result<()> {
        let original = "model: test\nmcp_servers:\n  other:\n    command: \"other\"\ntheme: dark\n";
        let merged = merge_hermes_config(
            original,
            &["drive".to_owned(), "gmail".to_owned()],
            Path::new("/usr/local/bin/agentsso"),
        )?;
        assert!(merged.contains("model: test"));
        assert!(merged.contains("  other:"));
        assert!(merged.contains("permitlayer_drive"));
        assert!(merged.contains("permitlayer_gmail"));
        assert!(merged.contains("# managed-by: permitlayer/hermes-stdio-v1"));
        assert!(merged.contains("theme: dark"));
        assert_eq!(
            merge_hermes_config(
                &merged,
                &["drive".to_owned(), "gmail".to_owned()],
                Path::new("/usr/local/bin/agentsso"),
            )?,
            merged
        );
        Ok(())
    }

    #[test]
    fn hermes_merge_refuses_unrelated_key_collision() {
        let original = "mcp_servers:\n  permitlayer_drive:\n    command: \"evil\"\n";
        assert!(
            merge_hermes_config(
                original,
                &["drive".to_owned()],
                Path::new("/usr/local/bin/agentsso"),
            )
            .is_err()
        );
    }

    #[test]
    fn hermes_merge_refuses_unsupported_yaml_mapping_layouts() {
        for original in ["mcp_servers: {}\n", "\"mcp_servers\": {}\n"] {
            assert!(
                merge_hermes_config(
                    original,
                    &["drive".to_owned()],
                    Path::new("/usr/local/bin/agentsso"),
                )
                .is_err()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recorded_enrollment_is_exact_and_cannot_expand() -> anyhow::Result<()> {
        let journal = OnboardingJournal {
            schema_version: 1,
            user: "angie".to_owned(),
            uid: 502,
            agent: "hermes-angie".to_owned(),
            phase: "complete".to_owned(),
            services: vec![EnrolledService {
                service: "drive".to_owned(),
                connection_id: "01DRIVE".to_owned(),
                connection_name: "drive-refresh".to_owned(),
            }],
            capabilities: vec!["mcp-drive".to_owned(), "drive-download".to_owned()],
        };
        let mut exact = HermesArgs {
            user: "angie".to_owned(),
            agent: None,
            gmail: None,
            calendar: None,
            drive: Some("drive-refresh".to_owned()),
            replace_local_access: false,
            root_phase: true,
            target_phase: false,
            selected_services: Vec::new(),
            bridge_command: None,
        };
        apply_recorded_connections(&mut exact, &journal)?;
        assert_eq!(exact.drive.as_deref(), Some("01DRIVE"));

        exact.gmail = Some("gmail".to_owned());
        assert!(apply_recorded_connections(&mut exact, &journal).is_err());
        Ok(())
    }
}
