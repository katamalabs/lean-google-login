#!/usr/bin/env bash
#
# Verify that every place a version is written agrees with the release tag,
# before anything is published.
#
# Checks, all against the tag passed as $1 (e.g. "0.1.0"):
#   - the main plugin header `Version:`
#   - the LEAN_GOOGLE_LOGIN_VERSION constant
#   - the readme.txt `Stable tag:`
#   - a matching `== Changelog ==` entry (`= <version> =`) in readme.txt
#
set -euo pipefail

TAG=${1:-${GITHUB_REF_NAME:-}}
if [[ -z "$TAG" ]]; then
	echo "usage: $0 <version>   (or set GITHUB_REF_NAME)" >&2
	exit 1
fi

MAINFILE=${MAINFILE:-lean-sign-in-with-google.php}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

HEADER_VERSION=$(grep -i "^ \* Version:" "$MAINFILE" | head -1 | awk -F' ' '{print $NF}' | tr -d '\r')
CONST_VERSION=$(grep -i "LEAN_GOOGLE_LOGIN_VERSION" "$MAINFILE" | head -1 | sed -E "s/.*'([^']+)'.*/\1/" | tr -d '\r')
README_VERSION=$(grep -i "Stable tag:" readme.txt | head -1 | awk -F' ' '{print $NF}' | tr -d '\r')

echo "tag: $TAG"
echo "$MAINFILE header Version:    $HEADER_VERSION"
echo "LEAN_GOOGLE_LOGIN_VERSION:   $CONST_VERSION"
echo "readme.txt Stable tag:       $README_VERSION"

FAIL=0
if [[ "$HEADER_VERSION" != "$TAG" ]]; then
	echo "::error::Plugin header Version ($HEADER_VERSION) does not match the tag ($TAG)." >&2
	FAIL=1
fi
if [[ "$CONST_VERSION" != "$TAG" ]]; then
	echo "::error::LEAN_GOOGLE_LOGIN_VERSION ($CONST_VERSION) does not match the tag ($TAG)." >&2
	FAIL=1
fi
if [[ "$README_VERSION" != "$TAG" ]]; then
	echo "::error::readme.txt Stable tag ($README_VERSION) does not match the tag ($TAG)." >&2
	FAIL=1
fi
if ! grep -qE "^= ${TAG//./\\.} =$" readme.txt; then
	echo "::error::readme.txt has no changelog entry '= $TAG =' for this release." >&2
	FAIL=1
fi

if [[ "$FAIL" != "0" ]]; then
	echo "Version consistency check failed." >&2
	exit 1
fi

echo "All version markers agree on $TAG."
