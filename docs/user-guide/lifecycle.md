# Install, enroll, upgrade, and diagnose

PermitLayer separates the root daemon from the user account that runs an
agent. The normal lifecycle is intentionally small:

| Goal | Command | Runs as | Result |
|---|---|---|---|
| Install or repair the system service | `agentsso setup` | Starts as operator; asks for sudo | Stages and version-verifies the root LaunchDaemon, then reconciles persisted local enrollments |
| Connect a Google account | `agentsso connection add <service> ...` | Operator | Seals OAuth credentials inside PermitLayer |
| Enroll Hermes | `agentsso onboard hermes --user angie` | Operator; one sudo authorization | Creates/adopts bindings, immutable local consent, and target-owned secretless stdio config |
| Upgrade everything | `agentsso upgrade` | Operator; Homebrew then one sudo authorization | Upgrades the formula, activates the new daemon, and verifies convergence |
| Check the system daemon | `agentsso status` or `agentsso service status` | Any local user | Uses launchd/control health; a missing per-user PID file is not treated as a stopped system daemon |
| Diagnose installation drift | `agentsso doctor` | Operator | Reports service, state, policy, and version problems |

Hermes entries invoke `agentsso mcp bridge --service gmail|calendar|drive`.
The bridge has no bearer option. It derives
`/var/run/permitlayer/agent-<uid>.sock` from its effective UID, and the daemon
uses macOS peer credentials to map that UID to one enrolled agent plus exact
connection IDs. Existing consent is never widened during onboarding or an
upgrade. To change it, inspect `agentsso agent local-access list` and repeat
onboarding with `--replace-local-access` only after reviewing the new account
and capability set.

Both onboarding and upgrade write a small phase journal before durable work.
If either process is interrupted, run the same command again. Existing agents,
bindings, grants, and managed Hermes entries are adopted rather than duplicated.
Completed enrollment records remain in root-owned PermitLayer state so later
`setup` and `upgrade` runs can recreate per-UID sockets and managed bridge
entries using the exact prior connection IDs and capability set.

After onboarding, run `/reload-mcp` in Hermes. A missing per-user socket means
the enrollment or daemon reconciliation is unhealthy; it is never a reason to
create `~/.agentsso/agent-bearer.token`.

## Drive integrity and release smoke

Zero-byte PDF, XLSX, image, audio, video, and archive transfers fail by default
with `drive.integrity.empty_source`. Size and checksum failures use the distinct
codes `drive.integrity.truncated` and `drive.integrity.checksum_mismatch`.
`--allow-empty` is available for a deliberate structured placeholder and emits
a dedicated audit event. Legitimate empty text files do not require an override.

Before publishing a release, run the non-destructive XLSX round-trip as the
enrolled Hermes account (never as root):

```bash
sudo -u angie -H python3 scripts/smoke-hermes-drive-xlsx.py --connection drive
```

The fixture creates a uniquely named folder and workbook, exercises the
UID-authenticated MCP bridge plus CLI upload/download paths, checks SHA-256 and
opens the downloaded workbook with `openpyxl`, then permanently deletes only
those two test artifacts. If cleanup fails, it prints their exact IDs and name.
