# ADR 0005: Release automation identity — `HOMEBREW_TAP_TOKEN` PAT ownership

- **Status:** Accepted
- **Date:** 2026-04-22
- **Deciders:** Story 7.1 (Homebrew formula ship)
- **Relates to:** FR2 (Homebrew install on macOS), Story 7.1 Task 3 (`HOMEBREW_TAP_TOKEN` generation), `.github/workflows/release.yml` (`homebrew-publish` job)
- **Supersedes:** n/a

## Context

Story 7.1 adds a `homebrew-publish` job to the release pipeline that
pushes a regenerated `Formula/agentsso.rb` to
[`permitlayer/homebrew-tap`](https://github.com/permitlayer/homebrew-tap)
after every tagged release. The main repo's built-in `GITHUB_TOKEN`
cannot perform this write — it is scoped to
`permitlayer/permitlayer` only — so the job requires a
**cross-repository write credential** stored as the
`HOMEBREW_TAP_TOKEN` Actions secret.

Two credential-ownership models are viable:

### Option A — Personal fine-grained PAT (solo-maintainer)

The PAT is minted by `@botsdown` (Austin's personal account) and
scoped to exactly `permitlayer/homebrew-tap` with
`contents: write` and nothing else.

**Pros:**
- Zero setup cost — Austin already owns write on both repos.
- GitHub's fine-grained PAT model supports per-repo scoping; the
  blast radius is limited to the tap.
- Simpler audit: one human, one PAT, one secret.

**Cons:**
- Ties release automation to a specific human account. If Austin
  leaves the project or loses account access, the release path
  stops until a new maintainer re-mints the PAT under their own
  account.
- Rotation requires Austin's active involvement.
- Does not scale past a single maintainer: a second committer
  would not have their PAT recognized as the release-automation
  identity without also updating the secret.

### Option B — Dedicated bot account

A separate GitHub account (suggested name `permitlayer-releasebot`)
is invited to the `permitlayer` org with write on exactly the tap
repo. The PAT is minted by the bot.

**Pros:**
- Release automation identity is decoupled from any individual.
- Matches conventions of the `action-homebrew-tap` /
  `homebrew-releaser` ecosystem and most mature tap-managing
  repos.
- Rotation is a maintenance task the bot account lives for — no
  interference with personal workflows.

**Cons:**
- GitHub's free plan does not include SSO-enforced bot-account
  constraints; in practice the bot account is a plain user
  account requiring its own 2FA device (hardware key or TOTP).
- One more account to secure (2FA, recovery codes, email).
- Premature for a pre-v0.2.0 solo-maintained project —
  infrastructure overhead ahead of need.

## Decision

**Option A for v0.2.0. Document the migration path to Option B and
revisit when either (a) a second maintainer joins the project, or
(b) the first stable (`v1.0.0`) release is cut.**

The `HOMEBREW_TAP_TOKEN` is minted by `@botsdown` as a fine-grained
PAT scoped to `permitlayer/homebrew-tap` with the `contents: write`
permission (and only that), expiring in 90 days with a calendar
reminder 14 days before expiry to rotate.

If either trigger condition hits, we migrate to Option B by:

1. Creating `@permitlayer-releasebot` (or equivalent name).
2. Inviting it to the `permitlayer` org with write on only
   `permitlayer/homebrew-tap`.
3. Minting a new fine-grained PAT from that account with the same
   scope.
4. Updating `HOMEBREW_TAP_TOKEN` Actions secret in
   `permitlayer/permitlayer` to the new PAT.
5. Revoking the `@botsdown`-owned PAT.
6. Updating this ADR's Status to `Superseded by ADR-NNNN` and
   writing the superseding ADR.

## Consequences

- **Release cadence depends on Austin's PAT staying valid.** If the
  PAT expires mid-release, the `homebrew-publish` job fails at the
  tap push step. The GitHub Release itself still ships (signed
  tarballs + `.minisig` sigs are produced by earlier jobs), and
  the `install/install.sh` curl|sh path stays functional. Only the
  tap is stale. Failure mode is **degraded, not broken**.
- **Rotation is a calendar task.** See `SECURITY.md` (`HOMEBREW_TAP_TOKEN`
  rotation runbook section) for the step-by-step.
- **Audit trail.** Every tap push commit is signed as
  `permitlayer release bot <release-bot@permitlayer.dev>`
  (set by the workflow's `git config user.name` / `user.email`).
  The underlying authentication is the PAT, not the committer
  identity — the committer field is cosmetic. GitHub's audit log
  will show the push as originating from `@botsdown` (the PAT
  owner) until we migrate to Option B.
- **Single point of failure acknowledged.** If Austin's account is
  compromised, the attacker can push to the tap (and to the main
  repo). Mitigation: hardware 2FA on the personal account;
  fine-grained PAT scope prevents broader damage; tap repo's `main`
  branch would still require the `HOMEBREW_TAP_TOKEN` (separate
  from Austin's cookie-jar auth) to push from outside the release
  workflow.

## References

- [GitHub docs: Fine-grained personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token)
- [`action-homebrew-tap`](https://github.com/Justintime50/action-homebrew-tap) — convention reference for tap-push identity.
- `_bmad-output/implementation-artifacts/7-1-homebrew-formula.md` §"Authentication — PAT-based tap push".
- `SECURITY.md` §"HOMEBREW_TAP_TOKEN rotation runbook".
