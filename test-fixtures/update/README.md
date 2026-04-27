# Story 7.5 — `agentsso update` test fixtures

**THESE KEYS ARE TEST-ONLY. DO NOT USE FOR ANY PRODUCTION SIGNING.**

`test-pubkey.pub` and `test-seckey.key` form a minisign keypair
generated specifically for the Story 7.5 apply-flow integration
test. The secret key is committed deliberately — its sole purpose
is to let the integration test build a real signed `.tar.gz`
archive at test runtime, which the `cli::update::verify::verify_minisign`
function then verifies via the
`AGENTSSO_UPDATE_PUBKEY_OVERRIDE`-pointed pubkey
(`cfg(debug_assertions)`-only seam).

## Why a committed test key is safe here

- The production trust root is `install/permitlayer.pub` — a
  completely different keypair. Production binaries embed THAT key
  via `include_str!`; the override env var is only read in debug
  builds.
- These keys cannot be used to forge releases against production
  installs. `agentsso update` (release build) ignores
  `AGENTSSO_UPDATE_PUBKEY_OVERRIDE` entirely.
- The keypair was generated with the password `"test"` (literal
  four-character string). The integration test passes this password
  to `SecretKeyBox::into_secret_key`. minisign 0.9.1 rejects
  `None`-passwords on key-load with "Key is not encrypted", which
  is why we use a known password here rather than `-W`.

## Re-generating

If these files ever need to be rotated:

```sh
cd test-fixtures/update
rm test-pubkey.pub test-seckey.key
echo -e "test\ntest" | minisign -G -p test-pubkey.pub -s test-seckey.key
```

(The `echo -e "test\ntest"` pipe answers the password prompt + the
confirmation prompt with the literal password `"test"`.)

Then update any test that hardcodes the keyid (the `untrusted comment`
line in `test-pubkey.pub` carries the new keyid).
