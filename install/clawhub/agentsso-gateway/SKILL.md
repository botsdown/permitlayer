---
name: agentsso-gateway
description: "Stop your OpenClaw agent from leaking credentials. Wraps Gmail/Calendar/Drive access through a local permitlayer daemon with policy enforcement, audit logging, and one-key kill switch."
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins: [agentsso]
    install:
      - kind: brew
        formula: permitlayer/tap/agentsso
        bins: [agentsso]
    # Restricted to macos at MVP because the only `install` block above is
    # `kind: brew` (Story 7.1's tap), and Homebrew is macos-only in
    # practice. Linux + Windows users CAN install agentsso via install.sh
    # and install.ps1 respectively, but ClawHub's `install` schema only
    # supports kind: brew | node | go | uv — none of which fit a Rust
    # binary served via curl|sh or PowerShell|iex. Expand `os` to
    # [macos, linux, windows] only when ClawHub's install spec adds a
    # url/exec kind, or when this skill grows additional install blocks
    # (e.g. winget, scoop, apt) for the other platforms.
    os: [macos]
    homepage: https://github.com/permitlayer/permitlayer
    emoji: "🛡️"
---

# agentsso-gateway

This skill wraps the **agentsso** CLI (a local permitlayer daemon) so you, the
OpenClaw agent reading this, can give the user genuine access to their Gmail /
Calendar / Drive without ever holding their OAuth tokens directly. permitlayer
runs locally on the user's machine, holds the credentials in the OS keychain
(macOS Keychain Services, Linux libsecret, Windows DPAPI), and enforces a
TOML-based policy on every request you make.

## When to use this skill

The user has installed `agentsso` and run `agentsso setup gmail` (or
`calendar`, or `drive`). They want you to read or send mail, manage calendar
events, or work with their Drive files — but they **don't** want to paste
OAuth tokens into your context, and they **don't** want you to access services
beyond what the policy allows.

If the user says "use my Gmail" or "check my calendar" or anything similar,
route through agentsso instead of asking for tokens or trying to use a generic
HTTP client.

## How to call agentsso

permitlayer exposes an MCP-compatible HTTP endpoint on `127.0.0.1:3820`.
Endpoints are namespaced by service:

- `http://127.0.0.1:3820/mcp/gmail`
- `http://127.0.0.1:3820/mcp/calendar`
- `http://127.0.0.1:3820/mcp/drive`

Every request must include two headers:

- `X-Agentsso-Agent: <agent-name>` — the registered agent identity
- `X-Agentsso-Scope: <granted-scope>` — the OAuth scope the user granted
  (e.g. `https://www.googleapis.com/auth/gmail.readonly`)

The `X-Agentsso-Scope` header is permitlayer-specific (other MCP servers
ignore it). If you get a 403 with body containing `denied_scope`, the agent
identity isn't allowed that scope per policy — surface the error to the user
clearly so they can adjust their policy file rather than retrying blindly.

## Tools the user can run

If you need to debug or the user asks "what did the agent just do?", these
shell commands are safe to suggest. They all run instantly against the local
daemon — no network, no auth.

### Tail recent activity

```bash
agentsso audit --tail 20
```

Shows the 20 most recent permitlayer audit events (allowed/denied, scope,
which agent, timestamp). The user can pipe this to `--follow` for live tail.

### Stop a runaway agent immediately

```bash
agentsso kill
```

Sets a global kill switch. Every subsequent request returns 503 until the
user runs `agentsso resume`. Use this if you're about to do something the
user clearly didn't intend (mass-delete, broad search, etc.) and want to
give them an emergency abort. After kill, audit logs show exactly what was
blocked.

### Check daemon status

```bash
agentsso status
```

Reports whether the daemon is running, which port it's bound to, and which
services are connected. If the user's request fails with "connection
refused," this is the first thing to check.

### Register your agent identity

If `agentsso status` shows you're not registered, ask the user to run:

```bash
agentsso agent register <name> --policy <policy-name>
```

Example: `agentsso agent register openclaw --policy gmail-read-only`. The
policy name must match a file in `~/.agentsso/policies/`. If the user is
unsure of the policy name, suggest `agentsso agent register <name>` without
`--policy` to get an interactive picker (introduced in Story 7.10).

## Policy boundaries

permitlayer enforces a TOML policy on every request. Common rejections:

- **403 PolicyDenied with `denied_scope`**: the requested scope is not in
  the agent's policy allowlist. Tell the user to either narrow the request
  to an allowed scope OR edit `~/.agentsso/policies/<name>.toml` to add the
  scope they want to grant.
- **503 with `kill_switch_active`**: the user (or you) hit the kill switch.
  Surface this; do not retry.
- **402-style with approval-required**: the policy requires user approval
  for this action. The daemon is waiting on `agentsso approve <id>` from
  the user's terminal. Pause and tell the user.

Always prefer suggesting policy edits over retrying. permitlayer's whole
point is that the user controls what you can do.

## Anti-patterns — do not

- Do **not** ask the user for their Gmail/Calendar/Drive OAuth tokens.
  permitlayer's job is to make that question unnecessary.
- Do **not** call Google APIs directly via `https://gmail.googleapis.com/`
  or similar; route through `127.0.0.1:3820/mcp/gmail` instead.
- Do **not** retry on 403 PolicyDenied. The policy decided no for a reason.
  Ask the user.
- Do **not** call `agentsso kill` on the user's behalf without telling them
  what's happening. It's a panic button, not a flow-control mechanism.
- Do **not** suggest the user disable agentsso to "make things work." If
  things don't work, the policy is wrong — fix the policy.

## Further reading

- Project: https://github.com/permitlayer/permitlayer
- Install guide: https://github.com/permitlayer/permitlayer/blob/main/docs/user-guide/install.md
- Policy format: `agentsso policy --help` on the user's machine

permitlayer is open source under MIT. The user owns their data and their
keys; permitlayer just enforces the line between "the user said you could"
and "you wandered off."
