# Release verification log

One entry per release that has been end-to-end verified against the
customer-facing install paths. Appended to as part of each release's
manual AC pass.

Format: `## YYYY-MM-DD — <tag> — Story <N.N>` with a brief result
summary. Link to the GitHub Release. Note any deviations from the
expected flow.

---

## (pending) — `v0.2.0-rc.1` — Story 7.1

Will record:

- `brew tap permitlayer/tap && brew install permitlayer/tap/agentsso` on
  fresh macOS ARM64 — timing, version output.
- `brew install` post-install caveats block — verifies the text matches
  `scripts/homebrew-service-block.rb.snippet`.
- `brew services start agentsso` → `agentsso status running` → time-to-
  ready (AC #3 target: <10s).
- `brew services stop agentsso` → `agentsso status not running`.
- `brew audit --strict` + `brew style` in the CI runner (AC #5).
- Binary size check against NFR48 (compressed <30MB, uncompressed <80MB).
- Install wall-clock time against AC #9 (<30s on broadband).
