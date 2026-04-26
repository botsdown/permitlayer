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

## 2026-04-26 — `v0.3.0-rc.1` — Story 7.2 (Windows installer + ClawHub skill)

**First Windows release.** Adds `x86_64-pc-windows-msvc` to dist's targets,
ships `install/install.ps1` (PowerShell installer mirroring install.sh's
UX-DR9 ProgressSteps + sha256-sidecar verification), wires
`windows-publish-smoke` job into release.yml, and adds the
`agentsso-gateway` ClawHub skill folder. No Authenticode signing yet —
sha256 sidecar verification only.

### Pipeline verification

**ALL 10 JOBS GREEN ON FIRST TRY** (release run
[`24964944269`](https://github.com/permitlayer/permitlayer/actions/runs/24964944269)).
Story 7.1 found 12 latent bugs on its first real release-pipeline run; this
one had **zero**. The macOS-side review caught everything.

| Job | Result | Notes |
|-----|--------|-------|
| `plan` | ✓ | dist 0.31 emits Windows artifact in manifest |
| `build-local-artifacts (aarch64-apple-darwin)` | ✓ | unchanged from v0.2.1 baseline |
| `build-local-artifacts (x86_64-apple-darwin)` | ✓ | unchanged |
| `build-local-artifacts (x86_64-pc-windows-msvc)` | ✓ | **first cargo-build-on-Windows for permitlayer.** Keystore + daemon + all 8 crates compiled cleanly under MSVC — confirms Story 4.4's `keyring` `windows-native` feature gate works in production. Closes AC #1. |
| `build-global-artifacts` | ✓ | dist regenerates `agentsso.rb` formula; not pushed (homebrew gate skip) |
| `sign` | ✓ | minisign signed all 3 platform zips/tarballs producing `.minisig` files |
| `host` | ✓ | GitHub Release `v0.3.0-rc.1` published with 15 assets (12 baseline + 3 new Windows assets) |
| `homebrew-publish` | ✓ (gated-skip) | hyphen-in-tag detected, `HOMEBREW_PUBLISH_PRERELEASES != 1`, `skip=1`, `Early exit for gated pre-release` exited 0. Tap untouched at v0.2.1 — confirmed via `git ls-remote permitlayer/homebrew-tap`. |
| `windows-publish-smoke` | ✓ | install.ps1 ran end-to-end on `windows-latest` against the published zip; sha256 verified; `agentsso --version` returned exactly `agentsso 0.3.0-rc.1`. "Windows installer smoke test PASSED". |
| `announce` | ✓ | |

### Release assets

15 total (12 baseline + 3 new Windows): `permitlayer-daemon-x86_64-pc-windows-msvc.zip` + `.minisig` + `.sha256`. dist 0.31's native sha256 sidecar emission worked transparently — AC #6 needed zero release.yml changes for sha256 (only the `windows-publish-smoke` job to actually USE the sidecar).

### Manual VM smoke deferred to Story 7.7

Story 7.2's scope is install correctness (binary builds + zip downloads + sha256 verifies + agentsso --version reports right). All of that is now empirically green. Runtime-side parity (DPAPI keystore round-trip, daemon-binds-127.0.0.1:3820, OAuth flow on Windows) is Story 7.7's domain per the cross-story fence in `_bmad-output/implementation-artifacts/7-2-windows-installer.md` Dev Notes §"Cross-story fences".

### Hypotheses that did NOT materialize

The 4 expected-drift items I listed in this section's pre-merge placeholder:

- ❌ "dist 0.31's Windows runner image may need PowerShell version pinning" — dist used `windows-latest` with PowerShell 7.4 cleanly, no pin needed.
- ❌ "install.ps1's Resolve-Version may rate-limit on GitHub API" — `windows-publish-smoke` set `$env:AGENTSSO_VERSION` explicitly so the API call was skipped (as designed).
- ❌ "Expand-Archive long-path failure on PS 5.1" — runner used PS 7.4, no long-path issue. Even if PS 5.1 had been used, install dir is `D:\a\_temp\agentsso-smoke\agentsso.exe` (well under MAX_PATH).
- ❌ "ANSI escapes mis-render in conhost" — `[Console]::IsOutputRedirected` returned true in CI (job logs are piped), so install.ps1 disabled colors automatically. No rendering issues.

### Workspace version reverted

After the rc shakedown was clean, workspace.package.version reverted 0.3.0-rc.1 → 0.2.1 (no actual stable bump pending in Story 7.2; the v0.3.0 stable cut is a separate event after Story 7.2 lands review). The published `v0.3.0-rc.1` GitHub Release stays as-is for posterity + as a downloadable proof of the install path.
