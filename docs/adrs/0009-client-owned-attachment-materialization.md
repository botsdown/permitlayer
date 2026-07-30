# ADR 0009 — Client-owned attachment materialization through MCP resources

**Status:** Accepted

**Date:** 2026-07-30

**Supersedes:** ADR-0008

## Context

ADR-0008 made the privileged PermitLayer daemon write decrypted Gmail
attachments beneath its state directory and return a local path. That path is
not a portable MCP contract, and on macOS it crosses an operating-system user
boundary: the daemon runs as root while Hermes runs as the operator. In
practice an attachment could download successfully and still be unreadable by
the agent.

Current Hermes releases support MCP embedded binary resources. Hermes
v2026.7.20 and later decode an `EmbeddedResource` blob into their own document
cache before exposing a readable path to file and PDF tools. This gives the MCP
caller ownership of storage location, permissions, lifetime, and cleanup.

## Decision

`gmail.attachments.get` returns a `CallToolResult` with:

- one MCP embedded `resource` content block containing the exact attachment
  bytes as the protocol's standard-base64 `blob`;
- a non-fetchable `permitlayer://attachment/...` resource identifier with a
  unique ULID and sanitized filename hint; and
- structured metadata containing `messageId`, `attachmentId`, `size`,
  `mimeType`, and `filename`, but no daemon-local `path`.

The base64 is protocol encoding inside the resource block, not ordinary text
for the model to process. Compatible clients materialize it and decide where
the file lives. Hermes v2026.7.20+ is the supported implementation.

PermitLayer keeps its existing authorization, attachment-size limit,
base64url validation, filename sanitization, and best-effort MIME metadata
lookup. Binary attachment responses continue to bypass the text scrubber so
scrubbing cannot corrupt the file.

PermitLayer no longer creates a media directory, changes attachment-file
ownership, returns server-local attachment paths, or runs an attachment TTL
sweeper. It also does not accept a caller-selected output path: allowing an MCP
caller to choose where a privileged daemon writes would create an arbitrary
file-write boundary. On the first upgraded start, the daemon removes the
legacy transient `media/` tree so files awaiting the former TTL sweep are not
left behind indefinitely.

## Consequences

- Hermes materializes files as its own OS user, so its PDF and file tools can
  read them without cross-user permissions.
- The attachment bytes traverse the MCP response, so the existing 50 MiB
  attachment limit remains relevant. They do not consume model context in
  clients that implement embedded-resource materialization.
- Clients without embedded-resource support cannot use the attachment tool and
  must upgrade; there is no daemon-file compatibility fallback.
- PermitLayer no longer retains decrypted Gmail attachment files after the MCP
  response completes. The client may retain its materialized copy according to
  its own cache and cleanup policy.

## Alternatives considered

- **Caller-selected output path.** Rejected because the privileged daemon
  would become an arbitrary file-writing primitive, with symlink, overwrite,
  ownership, and platform-specific path-policy risks.
- **User-owned fixed daemon path.** Rejected because it still couples the
  protocol to one host filesystem and one runtime user.
- **Inline base64 text.** Rejected because it expands model context and makes
  the agent responsible for decoding protocol payloads.
- **Keep ADR-0008 as a fallback.** Rejected because it preserves the original
  cross-user permission failure and continues retaining decrypted files.

## Revisit if

- PermitLayer supports remote clients that cannot receive embedded resources.
- Attachment streaming becomes part of the supported MCP/RMCP surface and
  materially reduces peak memory without reintroducing model-visible bytes.
- The supported Hermes version changes its resource-materialization contract.

## References

- ADR-0006 — macOS LaunchDaemon system-service.
- ADR-0007 — UDS-mediated credential-seal boundary.
- ADR-0008 — superseded media-file trust boundary.
- [Hermes MCP embedded-resource materialization](https://github.com/NousResearch/hermes-agent/blob/1d98f8dd95ab/tools/mcp_tool.py)
  — client implementation used for the v2026.7.20 compatibility floor.
