#!/usr/bin/env bash
# release-notes.sh TAG — prints the GitHub release notes for TAG (vX.Y.Z):
# the CHANGELOG.md section for X.Y.Z, followed by a compare link to the
# previous tag. It fails when the section is missing or empty, so a tag cut
# without its CHANGELOG entry never publishes a release. release.yml feeds the
# output to GoReleaser (--release-notes); ci.yml runs it on the newest section
# so a broken script surfaces on an ordinary PR, not at tag time.
set -euo pipefail

tag=${1:?usage: release-notes.sh vX.Y.Z}
version=${tag#v}
changelog=${CHANGELOG:-CHANGELOG.md}

# The section runs from its "## [X.Y.Z]" heading (exact version, so 0.3.0
# never matches 0.30.0) to the next "## [" heading; leading blank lines are
# dropped and command substitution trims the trailing ones.
body=$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found
' "$changelog" | sed -e '/./,$!d')

if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "release-notes.sh: $changelog has no (or an empty) section for $version" >&2
  exit 1
fi

printf '%s\n' "$body"

prev=$(git describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
if [ -n "$prev" ]; then
  repo=${GITHUB_REPOSITORY:-robsonek/berth}
  printf '\n---\n\n**Full changelog:** https://github.com/%s/compare/%s...%s\n' "$repo" "$prev" "$tag"
fi
