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
and starts the daemon. The service restarts if it crashes
(`keep_alive true`) and survives logout/login.

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
