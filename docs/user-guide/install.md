# Install

permitlayer ships the `agentsso` binary for macOS (ARM64 and x86_64).
Linux and Windows land in Story 7.2 / 7.7.

## macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
agentsso setup gmail
```

`brew install` downloads the architecture-matched tarball from
GitHub Releases, verifies its SHA256 digest (embedded in the
formula), and installs `agentsso` at:

- **Apple Silicon:** `/opt/homebrew/bin/agentsso`
- **Intel:** `/usr/local/bin/agentsso`

### Running as a Homebrew-managed service

Homebrew can register the daemon as a `launchd` user-service:

```sh
brew services start agentsso
```

This generates `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist`
and starts the daemon. The service restarts only on real crashes
(`keep_alive crashed: true` — signal-killed exits like SIGSEGV,
SIGABRT, OOM-kill) and survives logout/login. Deliberate non-zero
exits — e.g. `agentsso start`'s exit-3 when another instance is
already bound to the port — are NOT respawned, so a configuration
conflict with a manually-started daemon shows up as a single
`error 78` row in `brew services list` rather than a respawn loop.

Check status with `brew services list` or `agentsso status`.

To stop:

```sh
brew services stop agentsso
```

### Upgrading

```sh
brew upgrade agentsso
```

If the service is running, `brew` stops it, installs the new
binary, and you can restart with `brew services start agentsso`.

### Uninstalling

```sh
brew services stop agentsso   # if the service is running
brew uninstall agentsso
brew untap permitlayer/tap    # optional
```

`brew uninstall` does NOT remove `~/.agentsso/` — your vault,
credentials, and audit log stay put. Remove them manually if you
want a full clean:

```sh
rm -rf ~/.agentsso
```

(This deletes encrypted credentials, the vault master key, and
audit history. Only do this if you intend to re-run
`agentsso setup gmail` from scratch.)

## macOS / Linux — curl | sh

The `install/install.sh` one-liner is the non-Homebrew path. It
downloads the latest signed tarball from GitHub Releases, verifies
the ed25519 signature via minisign, and drops the binary at
`/usr/local/bin/agentsso`.

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
```

Pin to a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh -s -- --version 0.2.0
```

See `install/install.sh` for the full flag set.

## Build from source

Requires Rust (toolchain version pinned in `rust-toolchain.toml`).

```sh
git clone https://github.com/permitlayer/permitlayer.git
cd permitlayer
./scripts/bootstrap.sh   # installs toolchain + nextest + lld
cargo build --release -p permitlayer-daemon
cp target/release/agentsso /usr/local/bin/agentsso
```

## Autostart — two mechanisms, pick one

permitlayer offers two distinct autostart paths on macOS. They are
**mutually exclusive** — if you enable both, two daemons will try
to bind port 3820 and one will crash-loop.

| Path | Label | Enabled by | Managed by |
|------|-------|-----------|-----------|
| Homebrew service | `homebrew.mxcl.agentsso` | `brew services start agentsso` | `brew services ...` |
| Standalone autostart | `dev.agentsso.daemon` | `agentsso autostart enable` | `agentsso autostart ...` |

`brew services` is the right choice if you already use Homebrew
for lifecycle management of other services. The standalone path
(shipping in Story 7.3) works regardless of whether Homebrew is
installed.

If you switch mechanisms, disable the old one first:

```sh
# Switching from brew services → standalone:
brew services stop agentsso
agentsso autostart enable

# Switching from standalone → brew services:
agentsso autostart disable
brew services start agentsso
```

### Third collision case: manual `agentsso start` + `brew services start`

There's also a third way to collide that the table above doesn't cover:
running the daemon **manually in a terminal** (`agentsso start`) and then
trying to take it over with `brew services`.

**Symptom:** `brew services start agentsso` reports "Successfully started"
but `brew services list` shows the agentsso row in `error` state with exit
code 78. Nothing seems to work; `agentsso status` shows the daemon is
running but you can't manage it via brew.

**Why it happens:** The manual `agentsso` already has port 3820 bound. When
launchd tries to start a second instance via `brew services`, the daemon
detects the conflict via its PID-file check and exits with code 3 — a
deliberate "won't start, can't take over" signal. v0.2.1+ formulas
respect this and don't respawn-loop, but the launchd job still records
the error.

**Recovery:**

```sh
# Verify nothing is hung:
agentsso status                           # may show running

# Stop the manual instance:
agentsso stop                             # graceful SIGTERM, blocks <10s

# Now brew services can take over cleanly:
brew services start agentsso

# Always verify after a start:
brew services list | grep agentsso        # expect: started (not error)
```

**Diagnostic when in doubt:** the daemon's startup error message lands in
`/opt/homebrew/var/log/agentsso.log` (Apple Silicon) or
`/usr/local/var/log/agentsso.log` (Intel). `tail -n 20 <path>` after a
failed `brew services start` shows exactly which conflict was detected.

The general rule: **`brew services list | grep agentsso` is the
authoritative status check.** `brew services start`'s "Successfully
started" message means launchd accepted the request, not that the
daemon is actually running under brew's management. Verify after every
start.
