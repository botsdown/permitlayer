//! GitHub Releases API client for `agentsso update`.
//!
//! Hits `https://api.github.com/repos/botsdown/permitlayer/releases/latest`
//! (matching the same `REPO_OWNER`/`REPO_NAME` constants the curl|sh
//! installer hardcodes at `install/install.sh:17-18`) to discover
//! the latest non-draft, non-prerelease release.
//!
//! # Test seam
//!
//! `AGENTSSO_GITHUB_API_BASE_URL` overrides the API base URL, but
//! ONLY in `cfg(test)` builds OR when `cfg(feature = "test-seam")`
//! is set on the crate. A production runtime override would let an
//! attacker who can set environment variables redirect the update
//! flow at a malicious release stream.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

/// Production API base URL.
pub(crate) const PRODUCTION_API_BASE_URL: &str = "https://api.github.com";

/// Repo path (relative to the API base). Matches `install/install.sh:17-18`.
pub(crate) const REPO_PATH: &str = "/repos/botsdown/permitlayer";

/// Resolve the API base URL.
///
/// In `cfg(debug_assertions)` builds, honors `AGENTSSO_GITHUB_API_BASE_URL`
/// so integration tests can point a subprocess-spawned `agentsso
/// update` at a `mockito` mock server. Release builds (the only
/// thing real users ever run) ignore the env var entirely so an
/// attacker who can set env vars cannot redirect the update flow at
/// a malicious release stream.
///
/// Mirrors the `AGENTSSO_TEST_FROZEN_DATE` pattern at
/// `cli/connectors/new.rs::scaffold_date` — same threat model, same
/// debug-only seam.
pub(crate) fn api_base_url() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(override_url) = std::env::var("AGENTSSO_GITHUB_API_BASE_URL") {
            return override_url;
        }
    }
    PRODUCTION_API_BASE_URL.to_owned()
}

/// Test seam — explicit base URL parameter so unit tests don't need
/// `unsafe { env::set_var }` to drive the URL resolution.
///
/// Used by [`fetch_latest_release_with`] in the test paths AND by the
/// integration test (which still uses the env var via `cfg(test)` for
/// subprocess-spawned `agentsso update` runs against a mockito server
/// — the env var is the cross-process mechanism).
#[cfg(test)]
pub(crate) fn api_base_url_with(override_url: Option<&str>) -> String {
    match override_url {
        Some(url) => url.to_owned(),
        None => api_base_url(),
    }
}

/// Subset of the GitHub Releases response we care about.
///
/// Field-by-field justification — each field has a single consumer:
/// - `tag_name` → version-comparison + canonical "what version" label.
/// - `name` → human-readable release title (printed in the check-only
///   summary).
/// - `body` → release notes (printed truncated in the check-only
///   summary).
/// - `published_at` → relative-time line in the check-only summary.
/// - `draft` + `prerelease` → skip non-stable releases. We use the
///   `/releases/latest` endpoint which already filters these, but
///   keep the fields so the deserializer warns if GitHub ever drops
///   them.
/// - `assets[]` → which platform-target artifact + minisig to fetch.
///
/// We deserialize through `serde_json::Value` rather than this struct
/// directly so that a future GitHub schema change adding a required
/// field doesn't break the update flow on every running binary.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ReleaseInfo {
    pub(crate) tag_name: String,
    pub(crate) name: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) published_at: Option<String>,
    #[serde(default)]
    pub(crate) draft: bool,
    /// `prerelease` is read by GitHub's `/releases/latest` endpoint
    /// (which already filters prereleases out), but we keep the
    /// field so the deserializer doesn't reject a future GitHub
    /// schema change that adds it back. Reading it is intentional
    /// belt-and-braces.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) prerelease: bool,
    #[serde(default)]
    pub(crate) assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ReleaseAsset {
    pub(crate) name: String,
    pub(crate) browser_download_url: String,
    pub(crate) size: u64,
}

impl ReleaseInfo {
    /// Strip a leading `v` from `tag_name`. GitHub Releases conventions
    /// vary; cargo-dist tags as `v0.4.0` while the workspace version
    /// is `0.4.0`. Comparisons happen on the stripped string.
    pub(crate) fn version(&self) -> &str {
        self.tag_name.strip_prefix('v').unwrap_or(&self.tag_name)
    }

    /// Find the asset matching this binary's target triple.
    ///
    /// Returns `None` if no matching asset exists (release not yet
    /// published for this target — surface as a clean error in the
    /// orchestrator).
    ///
    /// **Review patch P12 (F14 — Edge):** exact prefix-match
    /// `agentsso-<target>.tar.gz` (or `.zip`) instead of the
    /// previous `name.contains(target)` substring scan, which
    /// would have collided with hypothetical future variant
    /// suffixes like `agentsso-x86_64-pc-windows-msvc-static.tar.gz`.
    pub(crate) fn asset_for_target(&self, target: &str) -> Option<&ReleaseAsset> {
        let expected_targz = format!("agentsso-{target}.tar.gz");
        let expected_zip = format!("agentsso-{target}.zip");
        self.assets.iter().find(|a| a.name == expected_targz || a.name == expected_zip)
    }

    /// Find the matching minisig sidecar for a given primary asset.
    /// Convention: `<asset>.minisig`.
    pub(crate) fn minisig_for(&self, primary: &ReleaseAsset) -> Option<&ReleaseAsset> {
        let expected_name = format!("{}.minisig", primary.name);
        self.assets.iter().find(|a| a.name == expected_name)
    }
}

/// Compare two version strings using semver. Strings WITHOUT a `v`
/// prefix.
///
/// Returns `Ordering::Less` when `current < latest` (an update is
/// available), `Equal` when versions match, `Greater` when the
/// running binary is somehow newer than the published release
/// (shouldn't happen in production but the orchestrator tolerates
/// it as "already on the latest").
///
/// **Review patch P13 (F15 — Blind + Edge):** on parse failure,
/// emit a `tracing::warn!` so the operator sees the malformed
/// version surface in the operational log. Lex-compare is still
/// the fallback (better than a panic), but silent acceptance was
/// the wrong default for a security-relevant compare.
pub(crate) fn compare_versions(current: &str, latest: &str) -> std::cmp::Ordering {
    use semver::Version;
    match (Version::parse(current), Version::parse(latest)) {
        (Ok(c), Ok(l)) => c.cmp(&l),
        (Err(e), _) => {
            tracing::warn!(
                target: "update",
                current,
                error = %e,
                "current version is not parseable as semver — falling back to lexicographic compare"
            );
            current.cmp(latest)
        }
        (_, Err(e)) => {
            tracing::warn!(
                target: "update",
                latest,
                error = %e,
                "latest version is not parseable as semver — falling back to lexicographic compare"
            );
            current.cmp(latest)
        }
    }
}

/// Build the `User-Agent`, `Accept`, and `X-GitHub-Api-Version`
/// headers GitHub's API expects.
fn default_headers(current_version: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let ua = format!("agentsso/{current_version}");
    headers.insert(USER_AGENT, HeaderValue::from_str(&ua).context("invalid UA header")?);
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
    Ok(headers)
}

/// Fetch the latest release. 30s total timeout; see story file Task
/// 2 for the rationale.
pub(crate) async fn fetch_latest_release(current_version: &str) -> Result<ReleaseInfo> {
    fetch_latest_release_with(current_version, &api_base_url()).await
}

/// Test seam — explicit base URL.
pub(crate) async fn fetch_latest_release_with(
    current_version: &str,
    base: &str,
) -> Result<ReleaseInfo> {
    let url = format!("{base}{REPO_PATH}/releases/latest");
    // **Review patch P14 (F16 — Blind + Edge):** limit redirect
    // policy to a single hop. `api.github.com` does not redirect
    // for `/releases/latest`; allowing arbitrary follow chains
    // would let a compromised intermediary (or the env-var test
    // seam in debug builds) chain through attacker-controlled
    // hosts that serve forged release JSON. Signature verification
    // is on the binary download (separate path), but the JSON
    // metadata gets emitted into the audit log + check-summary
    // verbatim — keeping it un-redirectable closes that hole.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(1))
        .default_headers(default_headers(current_version)?)
        .build()
        .context("reqwest client build failed")?;

    let response = client.get(&url).send().await.with_context(|| format!("GET {url} failed"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("GitHub Releases API returned {status} for {url}"));
    }

    // **Review patch P10 (F11 — Edge):** bound the JSON read.
    // `response.json()` allocates the full body before parsing; a
    // malicious or misbehaving server returning a 200 with a 2GB
    // body would OOM the runner. GitHub's real `/releases/latest`
    // response is tens of KB; 1MB is a 50× headroom that catches
    // accidents but allows for unusually-verbose release notes.
    const MAX_RELEASE_JSON_BYTES: usize = 1024 * 1024;
    let body_bytes =
        response.bytes().await.with_context(|| format!("read body from {url} failed"))?;
    if body_bytes.len() > MAX_RELEASE_JSON_BYTES {
        return Err(anyhow!(
            "GitHub /releases/latest body for {url} is {} bytes — exceeds {MAX_RELEASE_JSON_BYTES} byte cap",
            body_bytes.len()
        ));
    }
    let release: ReleaseInfo = serde_json::from_slice(&body_bytes)
        .with_context(|| format!("could not deserialize GitHub Releases response from {url}"))?;

    if release.draft {
        return Err(anyhow!(
            "GitHub /releases/latest returned a draft release ({}) — refusing to consider",
            release.tag_name
        ));
    }
    // **Review patch P9 (F10 — Edge + Auditor):** explicitly
    // refuse prereleases. The `/releases/latest` endpoint already
    // filters them server-side, but if a future GitHub change OR
    // a misconfigured asset stream surfaces one, the orchestrator
    // would silently apply a pre-1.0 release as a stable upgrade.
    // Operators opt into prereleases via the GitHub UI manually;
    // `agentsso update` is for stable releases only.
    if release.prerelease {
        return Err(anyhow!(
            "GitHub /releases/latest returned a prerelease ({}) — refusing to consider; \
             stable releases only",
            release.tag_name
        ));
    }
    Ok(release)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn version_strips_v_prefix() {
        let release = ReleaseInfo {
            tag_name: "v0.4.0".into(),
            name: None,
            body: None,
            published_at: None,
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        assert_eq!(release.version(), "0.4.0");

        let no_prefix = ReleaseInfo {
            tag_name: "0.4.0".into(),
            name: None,
            body: None,
            published_at: None,
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        assert_eq!(no_prefix.version(), "0.4.0");
    }

    #[test]
    fn compare_versions_handles_double_digit_minor_correctly() {
        // String-sort would put 0.10.0 < 0.2.0 — the bug semver
        // protects against. Verify the semver path runs.
        assert_eq!(compare_versions("0.2.1", "0.10.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("0.10.0", "0.2.1"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("0.4.0", "0.4.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_versions_falls_back_to_lex_on_parse_failure() {
        // Either side unparseable — semver crate rejects, fallback
        // to string comparison so we don't panic.
        assert_eq!(compare_versions("not-a-version", "0.4.0"), "not-a-version".cmp("0.4.0"));
    }

    #[test]
    fn asset_for_target_picks_archive_not_signature() {
        let release = ReleaseInfo {
            tag_name: "v0.4.0".into(),
            name: None,
            body: None,
            published_at: None,
            draft: false,
            prerelease: false,
            assets: vec![
                ReleaseAsset {
                    name: "agentsso-aarch64-apple-darwin.tar.gz".into(),
                    browser_download_url: "https://example.invalid/a.tar.gz".into(),
                    size: 12_345,
                },
                ReleaseAsset {
                    name: "agentsso-aarch64-apple-darwin.tar.gz.minisig".into(),
                    browser_download_url: "https://example.invalid/a.tar.gz.minisig".into(),
                    size: 100,
                },
                ReleaseAsset {
                    name: "agentsso-aarch64-apple-darwin.tar.gz.sha256".into(),
                    browser_download_url: "https://example.invalid/a.tar.gz.sha256".into(),
                    size: 64,
                },
            ],
        };
        let asset = release.asset_for_target("aarch64-apple-darwin").unwrap();
        assert_eq!(asset.name, "agentsso-aarch64-apple-darwin.tar.gz");

        let sig = release.minisig_for(asset).unwrap();
        assert_eq!(sig.name, "agentsso-aarch64-apple-darwin.tar.gz.minisig");
    }

    #[test]
    fn asset_for_target_returns_none_when_target_missing() {
        let release = ReleaseInfo {
            tag_name: "v0.4.0".into(),
            name: None,
            body: None,
            published_at: None,
            draft: false,
            prerelease: false,
            assets: vec![ReleaseAsset {
                name: "agentsso-x86_64-pc-windows-msvc.zip".into(),
                browser_download_url: "https://example.invalid/a.zip".into(),
                size: 12_345,
            }],
        };
        assert!(release.asset_for_target("aarch64-apple-darwin").is_none());
    }

    #[test]
    fn api_base_url_with_explicit_override() {
        // Use the explicit-parameter seam rather than `set_var` —
        // the daemon crate forbids unsafe code, and Rust 2024 made
        // `env::set_var` unsafe.
        assert_eq!(api_base_url_with(Some("https://localhost:9999")), "https://localhost:9999");
        assert_eq!(api_base_url_with(None), api_base_url());
    }

    #[test]
    fn production_api_base_url_is_github_dot_com() {
        // Lock in the production URL so a typo in the constant
        // surfaces as a test failure (not an in-the-wild outage).
        assert_eq!(PRODUCTION_API_BASE_URL, "https://api.github.com");
    }

    #[test]
    fn repo_path_matches_install_sh() {
        // install/install.sh:17-18 hardcodes botsdown/permitlayer.
        // If the project ever moves orgs, both this constant AND the
        // install scripts must update in lockstep.
        assert_eq!(REPO_PATH, "/repos/botsdown/permitlayer");
    }
}
