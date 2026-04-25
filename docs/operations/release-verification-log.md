# Release verification log

One entry per release that has been end-to-end verified against the
customer-facing install paths. Appended to as part of each release's
manual AC pass.

Format: `## YYYY-MM-DD — <tag> — Story <N.N>` with a brief result
summary. Link to the GitHub Release. Note any deviations from the
expected flow.

---

## 2026-04-22 — `v0.2.0` — Story 7.1

**First release.** Shipped as stable `v0.2.0` (not `v0.2.0-rc.1` as
originally planned — see Story 7.1 Dev Agent Record for why the tag
strategy changed). Both macOS architectures (ARM64 + x86_64) ship.

### Automated CI verification (pipeline run `24802657936`)

- `brew style --fix Formula/agentsso.rb` → zero offenses remaining.
  Replaces the `brew audit --strict` pre-push check (disabled for path
  arguments in modern Homebrew; see Story 7.1 Dev Agent Record).
- `brew tap permitlayer/tap && brew install permitlayer/tap/agentsso`
  on the CI `macos-14` runner — succeeded. `agentsso --version`
  returned `0.2.0`.
- `brew services` lifecycle NOT exercised in CI (launchd is absent
  on ephemeral runners). Covered by real-machine manual verification
  below.

### Real-machine manual verification

**macOS ARM64 (Apple Silicon, `austinlowry@mac`, dev machine):**

- Install path confirmed end-to-end via the `homebrew-publish` job's
  smoke test on `macos-14` CI runner (same hardware class). `brew
  install` + `agentsso --version` = `0.2.0`.
- `brew services start agentsso` / `brew services stop agentsso`
  lifecycle not yet exercised locally. AC #3 pending.

**macOS Intel (x86_64, fresh user `angie@Angie`):**

- Initial install diagnostic: user reported `bad CPU type in
  executable` from `agentsso`. Root cause: pre-existing `/usr/local/
  bin/agentsso` from an earlier manual copy (arm64 binary) was
  shadowing the brew install. `brew list` showed no `agentsso`
  formula installed — brew had never actually run on that machine for
  this tap. After `sudo rm /usr/local/bin/agentsso` and a clean
  `brew tap permitlayer/tap && brew install permitlayer/tap/
  agentsso`, the x86_64 tarball installed correctly; `file
  /usr/local/bin/agentsso` reported `Mach-O 64-bit executable
  x86_64`. **Confirms the Intel arch branch of the formula works.**
- OAuth setup flow via `agentsso setup gmail --oauth-client ...`
  succeeded end-to-end: tokens sealed to macOS Keychain, Gmail
  tested with 1 read, scopes granted.
- Daemon lifecycle + MCP proxy use pending further testing.

### Pending AC coverage (Story 7.1 Task 8)

- AC #9: timed `brew install` on broadband — **closed by 2026-04-25**
  (see v0.2.1 entry below). Austin's M-series Mac measured 14.8s
  end-to-end (within 30s budget; mostly Homebrew's auto-update
  overhead, real install ~3-4s).
- AC #5 strict: dist-generated formula passes `brew audit --strict`.
  Current behavior: formula passes `brew style --fix` + `brew style`
  (zero offenses), which covers the rubocop-style subset of
  `--strict`. Running `brew audit --strict` on a tapped formula is
  advisory-only (not in pipeline).

### Notes for future releases

- The pipeline is now fully green end-to-end. `v0.2.1+` should ship
  without manual intervention (barring new Story 1.12 scaffolding
  bugs, which this release flushed out comprehensively).
- Users who already manually copied `/usr/local/bin/agentsso` before
  v0.2.0 tap-install should `sudo rm` it first — `brew install`
  will not overwrite a file it didn't create.

---

## 2026-04-25 — `v0.2.1` — Story 7.1 hotfix

**Hotfix release.** Single-purpose: fix the `keep_alive true` →
silent-launchd-respawn-loop bug that surfaced during @angie's AC #3
verification on her Intel Mac. Bumped workspace 0.2.0 → 0.2.1, changed
formula's `service do` block to `keep_alive crashed: true`, expanded
caveats to cover the manual-`agentsso start` + `brew services start`
collision case. No Rust changes; daemon-side behavior was already
correct.

### Pipeline verification

- Run `24934994291` — **green first try**. All 7 jobs (`plan` →
  `build-local-artifacts` ×2 → `build-global-artifacts` → `sign` →
  `host` → `announce` + `homebrew-publish`) succeeded without retry.
- 12 GitHub Release assets published (same shape as v0.2.0).
- Tap commit `466d84cf agentsso v0.2.1` landed in
  `permitlayer/homebrew-tap`.
- Auto-PR #2 opened against main for `install/Formula/agentsso.rb`
  refresh (awaiting human review).
- CI smoke test (`brew tap && brew install && agentsso --version` on
  `macos-14`) reported `0.2.1`.

### Manual ACs covered by v0.2.1's existence

- **AC #4 (upgrade path)** unblocked. Any Mac with v0.2.0 already
  installed can now `brew upgrade agentsso` to validate the upgrade
  path naturally. Pending real-machine verification: <30s upgrade,
  formula refreshes, agentsso --version reports 0.2.1.

### Forensic note on the DSL form

The fix went through three iterations during planning before landing
on the correct syntax:

1. `keep_alive { successful_exit: false, crashed: true }` (planned)
   — silently drops keys per Homebrew's elsif chain at
   `service.rb:437–444`.
2. `keep_alive { crashed: true }` (briefly committed in fixture
   regen) — Ruby parses `{` as a block delimiter, not a hash literal,
   after a method name. `brew style` flagged it as a Lint/Syntax
   error.
3. `keep_alive crashed: true` (final, shipped) — implicit-paren
   method call with a hash arg. Maps to launchd's
   `KeepAlive: { Crashed: true }` — restart only on signal-killed
   termination.

Captured in story 7.1 Dev Agent Record + the v0.2.1 hotfix commit
(`5928eb6`) for posterity.

### Pending real-machine validation (post-merge of PR #2)

- AC #3 lifecycle re-test on @angie's Intel: install v0.2.1 (or
  `brew upgrade agentsso` from v0.2.0), trigger the conflict scenario
  (manual `agentsso start` + `brew services start agentsso`), confirm
  no silent respawn loop. `brew services list | grep agentsso`
  should NOT show `error 78` after the conflict — should report
  `none` or `stopped` cleanly.
- AC #4 upgrade-path validation on @austin's M-series:
  `brew upgrade agentsso` should pick up v0.2.1, replace the formula,
  preserve any running daemon's state.

These complete Story 7.1's manual AC closure. Story moves to `review`
on 2026-04-25; `code-review` workflow next.

---

## TBD — `v0.3.0-rc.1` — Story 7.2 (Windows installer + ClawHub skill)

**First Windows release.** Adds `x86_64-pc-windows-msvc` to dist's targets,
ships `install/install.ps1` (PowerShell installer mirroring install.sh's
UX-DR9 ProgressSteps + sha256-sidecar verification), wires
`windows-publish-smoke` job into release.yml, and adds the
`agentsso-gateway` ClawHub skill folder. No Authenticode signing yet —
sha256 sidecar verification only.

**This entry is a placeholder.** Task 8 of Story 7.2 will fill in the actual
shakedown results after pushing the rc tag. Expected drift (modeled on Story
7.1's first-release shakedown which found 12 latent bugs):

- dist 0.31's Windows runner image may need PowerShell version pinning.
- `install.ps1`'s `Resolve-Version` uses GitHub API which may rate-limit
  during CI runs (Story 7.1 didn't hit this; install.sh has the same code
  path). Fix: pass `$env:AGENTSSO_VERSION` explicitly in CI to skip the
  API call, which `windows-publish-smoke` already does.
- `Expand-Archive` on PS 5.1 may fail with long-paths if the runner
  doesn't have `core.longpaths` enabled. release.yml line 135 already has
  `git config --global core.longpaths true` for the build step but not
  the smoke step — may need to add.
- ANSI escape rendering on `windows-latest` conhost may be off by default
  in some PS versions; install.ps1's color block falls back to no-color
  when output is redirected (CI logs are redirected), so this should be
  invisible in CI but worth confirming.

### Pre-shakedown smoke (run from author's macOS box, 2026-04-25)

- `dist plan` confirms Windows artifact name `permitlayer-daemon-x86_64-pc-windows-msvc.zip` + `.sha256` sidecar.
- `actionlint .github/workflows/release.yml` clean on the new `windows-publish-smoke` job.
- `actionlint .github/workflows/ci.yml` clean on the new `windows-installer-test` job.
- `install/clawhub/agentsso-gateway/SKILL.md` YAML frontmatter parses.
- Local `cross`-build verification skipped per user-confirmed Path A — CI is the source of truth.

### Manual VM smoke pending (Task 6 of Story 7.2)

Austin to spin up a Windows 10/11 VM (Docker available; could be Parallels,
UTM, or cloud-VM), run `irm <release-url>/install.ps1 | iex` against the
v0.3.0-rc.1 release, confirm:

- Daemon starts, binds 127.0.0.1:3820.
- `agentsso status` reports running.
- `agentsso setup gmail` (if user wants to go that far) seals tokens to
  Windows Credential Manager (DPAPI).
- `-Autostart` shortcut creates `agentsso.lnk` in Startup folder.
- `irm | iex` flow works without `Set-ExecutionPolicy` mutation.

Document drift in this entry after the run.
