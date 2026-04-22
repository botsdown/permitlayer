#!/bin/sh
# patch-homebrew-formula.sh — inject service + caveats blocks into a
# dist-generated Homebrew formula.
#
# dist (cargo-dist 0.31) generates a Homebrew formula from a fixed Jinja
# template (cargo-dist/templates/installer/homebrew.rb.j2) that does NOT
# emit `service do` or `caveats` blocks. Story 7.1 requires both: users
# need caveats to know which next-command to run, and `brew services
# start agentsso` needs a `service do` block to register a launchd plist.
#
# This script reads a dist-generated .rb file and injects the Ruby
# snippet from scripts/homebrew-service-block.rb.snippet immediately
# before the final top-level `end` (the one that closes
# `class Agentsso < Formula`). The anchor is the first line that is
# exactly `end` with no leading whitespace — dist's template indents
# every inner-method `end` with two spaces, so this anchor is stable
# against changes inside methods.
#
# If the dist template ever changes shape such that the class-closing
# `end` is no longer flush-left, the unit test
# (scripts/test-patch-homebrew-formula.sh) will fail loudly and this
# script needs to be updated in lockstep with dist upgrades.
#
# Usage:
#   patch-homebrew-formula.sh <input.rb> [output.rb]
#
# If [output.rb] is omitted, writes to stdout.
#
# Exit codes:
#   0  patch applied successfully
#   1  input file missing or not a regular file
#   2  anchor (`^end$`) not found — dist template shape changed
#   3  snippet file missing

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNIPPET_PATH="${SCRIPT_DIR}/homebrew-service-block.rb.snippet"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <input.rb> [output.rb]" >&2
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-/dev/stdout}"

if [ ! -f "$INPUT" ]; then
    echo "error: input file not found: $INPUT" >&2
    exit 1
fi

if [ ! -f "$SNIPPET_PATH" ]; then
    echo "error: snippet file not found: $SNIPPET_PATH" >&2
    exit 3
fi

# Verify the class-closing anchor exists before touching anything.
if ! grep -q '^end$' "$INPUT"; then
    echo "error: anchor '^end$' not found in $INPUT" >&2
    echo "       dist template shape may have changed; update this script." >&2
    exit 2
fi

# Inject the snippet before the first flush-left `end`. awk is more
# robust than sed here because we can guard against multiple anchors
# (the snippet itself contains `end` tokens inside heredocs, but we
# process the file before emitting the snippet, so the `done` flag
# only fires once on the input's class-closing `end`).
awk -v snippet_path="$SNIPPET_PATH" '
BEGIN {
    # Read the snippet into memory once.
    snippet = ""
    while ((getline line < snippet_path) > 0) {
        snippet = snippet line "\n"
    }
    close(snippet_path)
    patched = 0
}
/^end$/ && !patched {
    # Emit the snippet immediately before the class-closing `end`,
    # separated by a blank line for readability.
    printf "\n%s", snippet
    patched = 1
}
{ print }
' "$INPUT" > "$OUTPUT"
