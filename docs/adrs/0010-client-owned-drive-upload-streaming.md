# ADR-0010: Client-owned Drive upload streaming

## Status

Accepted.

## Context

MCP tool arguments are JSON and Hermes does not currently implement a
standard client-to-server binary attachment input. Passing base64 through a
tool call expands the model context, while accepting a local `media_body`
path would let the privileged daemon read arbitrary caller-selected files.
Returning Google's resumable session URI to the client would also delegate a
write capability that cannot be revoked promptly by PermitLayer's kill switch
or binding policy.

## Decision

Binary Drive uploads use `agentsso drive upload`. The unprivileged CLI opens
and hashes the local file. It creates an authenticated PermitLayer upload
session and sends sequential 8 MiB chunks. The daemon owns the Google
resumable session URI in memory, rechecks the agent binding and `drive.file`
authority on every request, forwards each bounded chunk, and retains no file
content on disk. The limit is 250 MiB.

`drive.files.create` remains metadata-only and rejects content-like fields.
This keeps its existing MCP contract while making misuse fail loudly.

## Consequences

- The daemon never receives a local path and cannot perform an arbitrary
  privileged filesystem read.
- The model never receives base64 file content.
- Google credentials and resumable session capabilities remain daemon-owned.
- Kill, token, binding, policy, and connection revocation are enforced again
  at every chunk boundary.
- The daemon transiently holds one bounded chunk per active transfer; four
  concurrent chunks cap this new memory surface at approximately 32 MiB.
- Upload sessions are memory-only and expire after 30 minutes of inactivity.
  Daemon restart abandons incomplete sessions; Google eventually expires the
  unreachable upstream session.
