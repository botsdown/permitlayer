# ADR-0011: Secretless local peer authentication for Drive uploads

## Status

Accepted.

## Context

ADR-0010 correctly keeps caller paths, file bytes, Google credentials, and
resumable-session capabilities out of model-visible MCP payloads. Its initial
CLI transport still required a reusable PermitLayer bearer readable by the
invoking account. That is unacceptable when Hermes runs shell commands as the
same macOS user: any credential the helper can read can also be printed or
exfiltrated by the agent.

The root LaunchDaemon must remain the only Google credential holder, and the
Hermes account must not receive a reusable PermitLayer credential through a
file, environment variable, argv, stdin, output, or model context.

## Decision

On macOS system-service installations, each explicitly granted local account
gets an upload-only Unix socket at
`/var/run/permitlayer/agent-<uid>.sock`. The socket is owned by that user with
mode `0600` beneath a root-owned runtime directory. At accept time the daemon
captures `LOCAL_PEERCRED`; each request must match the listener UID and a
root-owned UID-to-agent grant. Root/system UIDs, missing grants, UID/username
drift, missing agents, and peer-credential failures deny access.

The socket router contains only Drive upload start, chunk, status, and cancel
routes. It fixes the required scope to `drive.file` server-side and ignores no
caller-selected agent, UID, scope, or socket path. Peer authentication inserts
the same `AgentId` used by bearer authentication and then converges on the
shared kill-switch, connection-tracking, binding-policy, and audit stack. The
Drive service retains its authoritative binding tier and granted-scope gates.

The unprivileged CLI opens and hashes the caller file and sends bounded bytes
over HTTP/1.1 on its effective UID's socket. The root daemon never opens a
caller-supplied path. The macOS CLI contains no implicit bearer fallback and
does not expose `--token-file`; authenticated TCP remains available to
non-macOS compatibility clients.

Operators manage the mapping through the control plane:

```sh
sudo agentsso agent local-access grant <agent> --user <macos-user>
sudo agentsso agent local-access list
sudo agentsso agent local-access revoke --user <macos-user>
```

Grant and revoke records are atomic and audited. A background listener manager
hydrates grants at daemon boot and reconciles grant/revoke changes without a
restart. Authorization is re-read on every request, so revocation denies the
next chunk even if socket cleanup is still draining.

## Consequences

- Hermes can upload local PDFs and other binaries without possessing a Google
  or PermitLayer reusable credential.
- Socket access cannot grant MCP, generic REST, health, or control-plane
  authority because those routes are absent from the local router.
- Each local request emits a peer audit event with agent, UID/GID, connection
  selector, method, and request path; no bearer, OAuth token, resumable URI,
  local source path, or file bytes are logged.
- Binding, tier, granted scope, policy, kill, concurrency, expiry, resumable
  reconciliation, and Drive size/MD5 validation continue to apply.
- UID reuse is fail-closed when the current username differs from the username
  captured at grant time; an operator must revoke and re-grant.
- Linux `SO_PEERCRED` and Windows named-pipe identity are future parity work.

## Alternatives rejected

- A bearer file, environment variable, stdin handoff, or wrapper: readable and
  replayable by a shell-capable agent.
- Reusing `control.sock`: expands the agent from fixed-function data access to
  administrative authority.
- Base64 MCP arguments: expand model context and expose file bytes.
- A daemon-opened local path: creates a privileged arbitrary-file-read deputy.

## Revisit triggers

- A supported macOS version changes `LOCAL_PEERCRED` semantics.
- Linux or Windows system-service deployments need secretless local parity.
- A fixed-function operation other than Drive upload needs this principal
  type; extend the narrow router deliberately rather than exposing generic
  proxy routes.
