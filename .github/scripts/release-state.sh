#!/usr/bin/env bash
# Prints the release state of the version in package.json (or $VERSION) for the commit $GITHUB_SHA:
#   new      - no tag and no release yet
#   retry    - the tag is already on $GITHUB_SHA but has no published release
#              (an earlier run died after GitHub created the tag, or the release was deleted)
#   released - a published release exists
# Exits 1, with an annotation, for every state a release must not be built from: a version that is not X.Y.Z
# (the in-app updater rejects any other tag), one that is not higher than every other release tag (X.Y.Z or
# vX.Y.Z: /releases/latest would be a lower version than an existing one, and every newer client would report that
# it is up to date), a tag on another commit with no release. Both the gate before the build and the publish job
# run it, so a stale "Re-run failed jobs" sees the current tags, not the ones from the first attempt.
#
# Env: GITHUB_REPOSITORY, GITHUB_SHA, GH_TOKEN (optional), GITHUB_API_URL (default https://api.github.com),
#      VERSION (default: package.json's, read with Node.js). Tags come from `git ls-remote --tags origin` in this
#      checkout.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
# shellcheck source=scripts/lib/version.sh
. "$ROOT/scripts/lib/version.sh"

: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
VERSION="${VERSION:-$(node "$ROOT/scripts/lib/package-version.mjs" get)}"

if ! version_valid "$VERSION"; then
	echo "::error file=package.json::Версия «$VERSION» должна быть X.Y.Z (без ведущих нулей и «v»): так называются релиз и его тег, и другой тег встроенное обновление не примет. Задайте её через scripts/make-release.sh." >&2
	exit 1
fi

# GET /releases/tags/{tag} only returns published releases, never drafts.
status="$(curl -sS --retry 3 --max-time 30 -o /dev/null -w '%{http_code}' \
	-H "Accept: application/vnd.github+json" \
	${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} \
	"${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY/releases/tags/$VERSION")" || true
case $status in
200)
	echo released
	exit 0
	;;
404) ;;
*)
	echo "::error::GitHub API ответил HTTP ${status:-000} на запрос релиза $VERSION." >&2
	exit 1
	;;
esac

refs="$(git -C "$ROOT" ls-remote --tags origin)" || {
	echo "::error::Не удалось прочитать теги origin (git ls-remote)." >&2
	exit 1
}
# The commit of the tag, an annotated one followed to it
tag_sha="$(tag_commit "$VERSION" <<<"$refs")"
highest="$(printf '%s\n' "$refs" | highest_tag "$VERSION")"

if [ -n "$highest" ] && ! version_gt "$VERSION" "${highest%% *}"; then
	echo "::error file=package.json::Версия $VERSION не выше существующего тега ${highest#* }. Поднимите её: scripts/make-release.sh." >&2
	exit 1
fi

if [ -z "$tag_sha" ]; then
	echo new
elif [ "$tag_sha" = "$GITHUB_SHA" ]; then
	echo retry
else
	echo "::error::Тег $VERSION указывает на $tag_sha, а не на $GITHUB_SHA, и релиза у него нет. Удалите тег или поднимите версию (scripts/make-release.sh)." >&2
	exit 1
fi
