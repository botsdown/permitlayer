# Security policy

## Reporting a vulnerability

Please report suspected security issues **privately** rather than in public
issues or pull requests.

- **Preferred:** open a private advisory at
  <https://github.com/permitlayer/permitlayer/security/advisories/new>.
- Alternate: email `austin@botsdown.com` with the subject line
  `permitlayer security report`.

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce (a minimal test case, proof-of-concept, or CVE-style
  writeup).
- The commit SHA or release tag you observed the issue on.

I'll acknowledge receipt within a few business days and give you an estimated
remediation timeline. You'll be credited in the release notes unless you
prefer to remain anonymous.

## Scope

permitlayer is an identity and data-protection layer for AI agents. The
following crates carry the security-critical logic and are in scope for
advisories:

- `crates/permitlayer-credential` — the sealed credential types and their
  trait discipline. CODEOWNERS gates changes here.
- `crates/permitlayer-keystore` — OS keychain integration (macOS Keychain,
  Linux Secret Service, Windows Credential Manager).
- `crates/permitlayer-vault` — file-backed encrypted vault
  (AES-GCM + HKDF + Argon2).
- `crates/permitlayer-oauth` — OAuth 2.1 client, PKCE flow, token refresh.
- `crates/permitlayer-core` — scrub engine, policy engine, audit log
  integrity.
- `crates/permitlayer-proxy` — HTTP proxy layer between MCP clients and
  upstream providers.
- `crates/permitlayer-daemon` — the `agentsso` binary and its CLI surface.
- `install/install.sh` — installer signature verification.

## Out of scope

- Connector plugins (`crates/permitlayer-connectors/src/js/**`) — these run
  inside the QuickJS sandbox defined in `crates/permitlayer-plugins`.
  Sandbox-escape bugs are in scope; bugs inside individual connector
  business logic generally are not.
- Development tooling (`xtask/`, `scripts/`, CI workflows).

## Supported versions

permitlayer is pre-1.0; only the latest release receives security fixes.
Once 1.0 ships, this section will be updated with an explicit support
window.

## Release signing

Release tarballs are signed with ed25519 via minisign. The verifying public
key is committed at `install/permitlayer.pub` and mirrored in
`install/install.sh`. Signature files are published alongside each release
artifact on GitHub. See `scripts/sign-release.sh` for the signing workflow.

## `HOMEBREW_TAP_TOKEN` rotation runbook

The release pipeline (`.github/workflows/release.yml`'s `homebrew-publish`
job) pushes the regenerated formula to
[`permitlayer/homebrew-tap`](https://github.com/permitlayer/homebrew-tap)
using a fine-grained PAT stored as the `HOMEBREW_TAP_TOKEN` Actions secret.
See [ADR 0005](docs/adrs/0005-release-automation-identity.md) for why this
credential exists and who owns it.

The PAT expires every 90 days. To rotate:

1. At <https://github.com/settings/personal-access-tokens/new>, mint a new
   fine-grained PAT with:
   - **Resource owner:** the account named in ADR 0005 (currently `@botsdown`).
   - **Repository access:** only `permitlayer/homebrew-tap`.
   - **Permissions:** `Contents: Read and write`. All others left at `No access`.
   - **Expiration:** 90 days.
2. Copy the token immediately — GitHub only shows it once.
3. Update the Actions secret:
   ```sh
   gh secret set HOMEBREW_TAP_TOKEN --repo permitlayer/permitlayer
   # paste the new PAT when prompted
   ```
4. Set a calendar reminder for 76 days out (14 days before the new expiry)
   to rotate again.
5. **Revoke the old PAT** at
   <https://github.com/settings/personal-access-tokens> — do not wait for
   natural expiry.

### Failure mode if the PAT is stale

If the PAT expires before rotation, the `homebrew-publish` job fails at the
tap push step with a 403. The effects:

- The GitHub Release itself still ships (signed tarballs + `.minisig`
  sigs are produced by earlier jobs).
- The `curl | sh` install path stays functional.
- `brew install permitlayer/tap/agentsso` continues to work but installs
  the *previous* version.
- `brew upgrade agentsso` is a no-op until the tap catches up.

This is a degraded but non-breaking state. Rotate the PAT and re-run the
workflow (`gh run rerun <run-id>`) to catch the tap up.
