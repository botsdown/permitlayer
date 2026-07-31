# ADR 0012: Complete Drive document lifecycle

## Status

Accepted.

## Context

Drive metadata operations and secretless uploads existed, but agents could not
safely download templates or replace file contents. The old
`files.get?alt=media` path converted arbitrary bytes through lossy UTF-8, and
shared-drive, trash, permission, revision, and change operations were partial.

## Decision

MCP downloads up to 16 MiB use embedded binary resources. Larger or durable
transfers use `agentsso drive download|export|revision-download`; the
unprivileged CLI writes atomically while the daemon relays bounded chunks and
never opens caller paths. Content replacement reuses resumable upload and
preserves the Drive file ID.

Blob and retained-revision downloads persist a user-owned partial file plus a
non-secret resume sidecar beside the destination. A later CLI invocation can
start a fresh daemon session and continue at the verified local offset.
Workspace exports restart from byte zero. Google Vids use Drive's
long-running `files.download` operation; OAuth-authenticated polling and the
signed download URI remain daemon-only, every redirect is validated as a
Google HTTPS destination, and OAuth headers are never sent to that URI.

Local-principal records are capability-versioned. Version-1 records migrate as
`drive-upload` only; download and replacement need explicit grants. Kernel peer
identity, capability, kill switch, binding, policy, connection, and scope are
re-evaluated on each 8 MiB request.

Arbitrary-file and sharing operations require a separately created
`full-control` connection paired only with a full-control binding. Permission
mutations additionally require explicit `drive.share` policy authority;
public/domain sharing and ownership transfer are not exposed.

`drive.files.delete` remains permanent for compatibility. New workflows use
`drive.files.trash` and `drive.files.restore`; `delete_permanently` is the
unambiguous permanent alias.

## Consequences

- Hermes can preserve XLSX templates without receiving a reusable credential.
- Existing connections, bindings, and local grants gain no authority.
- Transfer sessions are memory-only; resumable CLI downloads recover through
  a fresh session only when the source fingerprint still matches, without
  persisting credentials or Google capability URLs.
- Shared-drive file, permission, revision, and change calls send required flags.
- Comments, labels, watches, ownership transfer, public/domain sharing, CSE,
  and shared-drive administration remain outside this lifecycle.

## References

- ADR-0009 — client-owned MCP attachment materialization.
- ADR-0010 — client-owned Drive upload streaming.
- ADR-0011 — secretless local peer Drive uploads.
