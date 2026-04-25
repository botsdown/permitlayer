# agentsso-gateway — ClawHub skill

This folder is a [ClawHub](https://github.com/openclaw/clawhub) skill that
wraps the `agentsso` CLI so OpenClaw agents can use a user's Gmail / Calendar /
Drive without ever holding their OAuth tokens.

The deliverable is `SKILL.md` in this folder. Everything else in `install/`
(install.sh, install.ps1, Formula/agentsso.rb) is for the user-side install
of the `agentsso` binary; this skill is the agent-side instruction file.

## What's in here

- `SKILL.md` — the skill itself. YAML frontmatter declares the skill metadata
  (`metadata.openclaw.requires.bins: [agentsso]` plus a brew install spec).
  Body content tells the agent how to call `127.0.0.1:3820/mcp/<service>`,
  how to read audit logs, and what NOT to do.
- `README.md` — this file. Publish runbook.

## How users install it

```bash
clawhub install agentsso-gateway
```

ClawHub will:
1. Fetch the skill folder from `clawhub.ai`.
2. Extract `SKILL.md` (and any other text files) into the user's
   `<workdir>/skills/agentsso-gateway/`.
3. Notice `requires.bins: [agentsso]` and (if `agentsso` isn't on PATH)
   suggest the brew install per the `install` block.

## Publish runbook (for permitlayer maintainers — not auto-published by CI)

`agentsso-gateway` is **NOT** auto-published by the release pipeline.
Listing burn risk: publishing on a pre-stable build would burn the slug
on a half-working version. The skill must be published manually after
every stable `agentsso` release that the skill depends on.

### Prerequisites

- Have `clawhub` CLI installed: `bun install -g clawhub` (or via clawhub.ai's
  install instructions — confirm at https://clawhub.ai/install)
- Have a clawhub.ai account (GitHub OAuth, account age ≥ 14 days per
  https://github.com/openclaw/clawhub/blob/main/docs/security.md)
- Owner of the `agentsso-gateway` slug on clawhub.ai must be
  **[TBD — assign at first publish; document the account here]**

### Steps

```bash
# From the repo root:
cd install/clawhub/agentsso-gateway

# Authenticate (one-time):
clawhub login

# Verify what you're about to publish:
clawhub package validate .  # if available; otherwise read SKILL.md

# Publish:
clawhub package publish .
```

### Versioning

`SKILL.md` frontmatter has a `version: X.Y.Z` field. Bump it before each
publish per semver:

- **Patch** (1.0.0 → 1.0.1): typo fix, clarification, link update.
- **Minor** (1.0.0 → 1.1.0): new section, new tool documented (e.g. when
  agentsso ships a new CLI command the agent should know about).
- **Major** (1.0.0 → 2.0.0): breaking changes to the agentsso CLI surface
  this skill teaches (rare; would coincide with an agentsso 1.0+ release).

The skill version is **independent** of the agentsso binary version. The
brew install spec doesn't pin a version (it tracks the latest tap formula),
so the skill stays compatible with any agentsso release that doesn't break
the documented HTTP endpoints / CLI commands.

### After publish

- Verify the listing at `https://clawhub.ai/skills/agentsso-gateway`.
- Cross-link from the main project README so users know where to find it.
- Track install count via `clawhub inspect agentsso-gateway`.

## Story 7.2 Completion Notes — for Austin

**Do not run `clawhub package publish` during Story 7.2.** This file
exists so the publish path is documented when you're ready to ship.
Recommended trigger: after the first stable Windows release (Task 8 lands
v0.3.0 stable) confirms the install.ps1 path is solid. Until then, the
skill's `install: [{kind: brew, formula: permitlayer/tap/agentsso}]`
spec only works on macOS — Linux + Windows users would hit a missing
brew on install. If you publish before Linux/Windows install paths are
real, the skill is half-broken on two thirds of platforms.

When you do publish, also: assign an owner account, fill in the **TBD**
above, and add a note to `docs/operations/release-verification-log.md`
recording the publish event + skill version.
