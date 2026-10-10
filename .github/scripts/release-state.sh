#!/usr/bin/env bash
# Prints the release state of $VERSION for the commit $GITHUB_SHA:
#   new      - no tag and no release yet
#   retry    - the tag is already on $GITHUB_SHA but has no published release
#              (an earlier run died after GitHub created the tag)
#   released - a published release exists
# Exits 1, with an annotation, for every state a release must not be built from.
# Both the gate before the build and the publish job run it, so a stale
# "Re-run failed jobs" sees the current tags, not the ones from the first attempt.
set -euo pipefail

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error file=package.json::version '$VERSION' must be X.Y.Z; the in-app updater rejects any other tag." >&2
  exit 1
fi

# GET /releases/tags/{tag} only returns published releases, never drafts.
status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Accept: application/vnd.github+json" \
  ${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} \
  "${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY/releases/tags/$VERSION")
case $status in
  200) echo released; exit 0 ;;
  404) ;;
  *) echo "::error::GitHub API returned HTTP $status for release $VERSION." >&2; exit 1 ;;
esac

refs=$(git ls-remote --tags origin)
# The peeled "^{}" line follows an annotated tag, so the last match is the commit.
tag_sha=$(awk -v ref="refs/tags/$VERSION" '$2 == ref || $2 == ref "^{}" { sha = $1 } END { print sha }' <<<"$refs")
highest=$(awk '{ sub("^refs/tags/", "", $2) } $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ { print $2 }' <<<"$refs" \
  | { grep -vxF "$VERSION" || true; } | sort -V | tail -n1)

# /releases/latest would point at a lower version, and every newer client
# would report that it is already up to date.
if [ -n "$highest" ] && [ "$(printf '%s\n' "$highest" "$VERSION" | sort -V | tail -n1)" != "$VERSION" ]; then
  echo "::error file=package.json::version $VERSION is not higher than the existing tag $highest." >&2
  exit 1
fi

if [ -z "$tag_sha" ]; then
  echo new
elif [ "$tag_sha" = "$GITHUB_SHA" ]; then
  echo retry
else
  echo "::error::Tag $VERSION points at $tag_sha, not $GITHUB_SHA, and has no release. Delete the tag or bump the version." >&2
  exit 1
fi
