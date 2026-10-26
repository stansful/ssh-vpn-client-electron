#!/usr/bin/env bash
# Tests of .github/scripts/release-state.sh on the host: a throwaway clone of a local bare "origin" with tags,
# and a curl stub (first on PATH) in place of the GitHub API. Runs the script under $TEST_BASH (default: bash).
# A port of Shadow for OpenWrt's tests/unit/release/release-state_test.sh.
#
#   tests/release/release-state_test.sh          KEEP=1 keeps the temp dir
#
# Prints 'ok <name>' / 'not ok <name>: <why>' and exits non-zero on a failure.
# The conditions of check() are eval'd when it runs: single quotes on purpose, and the variables they read are
# set outside them.
# shellcheck disable=SC2016,SC2034
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TREE="$(cd "$HERE/../.." && pwd -P)"
BASH_BIN="${TEST_BASH:-bash}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/release-state-test.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
if [ -z "${KEEP:-}" ]; then trap 'rm -rf "$WORK"' EXIT; else echo "# work dir: $WORK"; fi

export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GH_TOKEN GITHUB_API_URL VERSION
mkdir -p "$HOME"

pass=0 fail=0
ok() {
	echo "ok $1"
	pass=$((pass + 1))
}
nok() {
	echo "not ok $1: $2"
	fail=$((fail + 1))
}
check() {
	if eval "$2"; then ok "$1"; else nok "$1" "rc=$RC; condition: $2; stdout: $OUT; stderr: $ERR"; fi
}
has_err() { case $ERR in *"$1"*) return 0 ;; esac; return 1; }
logged() { grep -qxF -- "$1" "$WORK/curl.log"; }

# The GitHub API: a release exists when $WORK/releases/<tag> does
mkdir -p "$WORK/bin" "$WORK/releases"
cat >"$WORK/bin/curl" <<'EOF'
#!/bin/sh
# curl stub: logs its arguments one per line and prints the HTTP status of the URL (its last argument):
# STUB_STATUS when set, else 200 when $STUB_RELEASES/<tag> exists, else 404. STUB_FAIL=1 fails like a refused
# connection (status 000, exit 7).
for a; do printf '%s\n' "$a"; done >"$STUB_LOG"
for a; do url=$a; done
if [ -n "${STUB_FAIL:-}" ]; then printf 000; exit 7; fi
if [ -n "${STUB_STATUS:-}" ]; then printf '%s' "$STUB_STATUS"
elif [ -e "$STUB_RELEASES/${url##*/}" ]; then printf 200
else printf 404
fi
EOF
chmod +x "$WORK/bin/curl"
export STUB_LOG="$WORK/curl.log" STUB_RELEASES="$WORK/releases"

# write_version <dir> <version>: package.json with that "version" (printf: the version may hold spaces)
write_version() {
	printf '{\n  "name": "seed",\n  "version": "%s",\n  "private": true\n}\n' "$2" >"$1/package.json"
}

# origin: A (tag 0.1.0) - B (annotated legacy tag v0.2.0) - C; package.json 0.3.0
SEED="$WORK/seed"
mkdir -p "$SEED/scripts/lib" "$SEED/.github/scripts"
cp "$TREE/scripts/lib/version.sh" "$TREE/scripts/lib/package-version.mjs" "$SEED/scripts/lib/"
cp "$TREE/.github/scripts/release-state.sh" "$SEED/.github/scripts/"
write_version "$SEED" 0.3.0
(
	set -e
	cd "$SEED"
	git -c init.defaultBranch=master init -q .
	git symbolic-ref HEAD refs/heads/master
	git add -A
	git commit -q -m A
	git tag 0.1.0
	git commit -q --allow-empty -m B
	git tag -a v0.2.0 -m legacy
	git commit -q --allow-empty -m C
	git tag not-a-release
	git init -q --bare "$WORK/origin.git"
	git push -q "$WORK/origin.git" master --tags
	git clone -q "$WORK/origin.git" "$WORK/repo"
) || {
	echo "not ok the test fixture could not be built"
	exit 1
}
REPO="$WORK/repo"
A=$(git -C "$REPO" rev-parse 0.1.0) C=$(git -C "$REPO" rev-parse HEAD)

# rs <GITHUB_SHA> [VAR=value...]: release-state.sh, run in REPO; sets OUT, ERR, RC
rs() {
	local sha="$1"
	shift
	OUT="$(cd "$REPO" && env PATH="$WORK/bin:$PATH" GITHUB_REPOSITORY=owner/repo GITHUB_SHA="$sha" "$@" \
		"$BASH_BIN" .github/scripts/release-state.sh 2>"$WORK/err")"
	RC=$?
	ERR="$(cat "$WORK/err")"
}
# tag_origin <tag> <commit> [annotated]: puts the tag on origin only (the clone does not fetch it)
tag_origin() {
	if [ -n "${3:-}" ]; then
		git -C "$WORK/origin.git" tag -f -a "$1" -m annotated "$2" >/dev/null
	else
		git -C "$WORK/origin.git" tag -f "$1" "$2" >/dev/null
	fi
}
untag_origin() { git -C "$WORK/origin.git" tag -d "$1" >/dev/null; }

rs "$C"
check "new: no release and no tag of package.json's 0.3.0" '[ $RC = 0 ] && [ "$OUT" = new ] && [ -z "$ERR" ]'
check "...asks the API for the release of 0.3.0, without a token" 'logged "https://api.github.com/repos/owner/repo/releases/tags/0.3.0" && ! grep -q Authorization "$WORK/curl.log"'
rs "$C" GH_TOKEN=secret-token GITHUB_API_URL=https://ghe.example.invalid/api/v3
check "...with GH_TOKEN as a bearer token and GITHUB_API_URL" '[ "$OUT" = new ] && logged "Authorization: Bearer secret-token" && logged "https://ghe.example.invalid/api/v3/repos/owner/repo/releases/tags/0.3.0"'
rs "$C" VERSION=0.4.0
check "VERSION overrides package.json" '[ "$OUT" = new ] && logged "https://api.github.com/repos/owner/repo/releases/tags/0.4.0"'

tag_origin 0.3.0 "$C"
rs "$C"
check "retry: the tag 0.3.0 is on GITHUB_SHA, no release" '[ $RC = 0 ] && [ "$OUT" = retry ]'
tag_origin 0.3.0 "$C" annotated
rs "$C"
check "retry: an annotated tag is followed to its commit" '[ $RC = 0 ] && [ "$OUT" = retry ]'
tag_origin 0.3.0 "$A"
rs "$C"
check "a tag 0.3.0 on another commit without a release is refused" '[ $RC = 1 ] && [ -z "$OUT" ] && has_err "::error::Тег 0.3.0 указывает на $A, а не на $C"'
touch "$WORK/releases/0.3.0"
rs "$C"
check "released: a published release, wherever its tag is" '[ $RC = 0 ] && [ "$OUT" = released ]'
rm -f "$WORK/releases/0.3.0"
untag_origin 0.3.0

rs "$C" VERSION=0.2.0
check "a version equal to a legacy tag v0.2.0 is refused" '[ $RC = 1 ] && has_err "::error file=package.json::Версия 0.2.0 не выше существующего тега v0.2.0"'
rs "$C" VERSION=0.1.5
check "a version below an existing tag is refused" '[ $RC = 1 ] && has_err "не выше существующего тега v0.2.0"'
tag_origin 0.9.0 "$A"
rs "$C"
check "a tag only on origin counts (0.3.0 below 0.9.0)" '[ $RC = 1 ] && has_err "Версия 0.3.0 не выше существующего тега 0.9.0"'
untag_origin 0.9.0
for v in v0.3.0 0.3 00.3.0 0.3.0-rc1 ""; do
	rs "$C" VERSION="$v"
	# an empty VERSION falls back to package.json, like an unset one
	if [ -z "$v" ]; then
		check "an empty VERSION reads package.json" '[ "$OUT" = new ]'
	else
		check "a malformed version '$v' is refused" '[ $RC = 1 ] && has_err "::error file=package.json::Версия «$v» должна быть X.Y.Z"'
	fi
done
write_version "$REPO" "0.3.0 "
rs "$C"
check "a version with a trailing space in package.json is refused" '[ $RC = 1 ] && has_err "Версия «0.3.0 » должна быть X.Y.Z"'
write_version "$REPO" 0.3.0

rs "$C" STUB_STATUS=500
check "an API error is refused" '[ $RC = 1 ] && has_err "::error::GitHub API ответил HTTP 500 на запрос релиза 0.3.0."'
rs "$C" STUB_FAIL=1
check "no answer from the API is refused" '[ $RC = 1 ] && has_err "HTTP 000"'
git -C "$REPO" remote set-url origin "$WORK/missing.git"
rs "$C"
check "unreadable origin tags are refused" '[ $RC = 1 ] && has_err "::error::Не удалось прочитать теги origin"'
git -C "$REPO" remote set-url origin "$WORK/origin.git"
rs "$C" GITHUB_REPOSITORY=
check "GITHUB_REPOSITORY is required" '[ $RC != 0 ] && [ -z "$OUT" ]'
rm "$REPO/package.json"
rs "$C"
check "no package.json and no VERSION: refused, nothing asked" '[ $RC != 0 ] && [ -z "$OUT" ] && has_err "не удалось прочитать package.json"'
write_version "$REPO" 0.3.0

# --- tag_commit (scripts/lib/version.sh): release-state.sh and the final tag check of release.yml's publish job
# read the tag's commit with it, from every tag of origin
# tc <tag> [ls-remote lines]: tag_commit under BASH_BIN, fed origin's `git ls-remote --tags` or the given lines;
# sets OUT, RC
tc() {
	local refs
	if [ $# -gt 1 ]; then refs=$2; else refs="$(git -C "$REPO" ls-remote --tags origin)"; fi
	OUT="$(printf '%s\n' "$refs" | "$BASH_BIN" -c '. "$1/scripts/lib/version.sh" && tag_commit "$2"' tc "$TREE" "$1")"
	RC=$?
	ERR=
}
B=$(git -C "$REPO" rev-parse 'v0.2.0^{commit}') B_TAG=$(git -C "$REPO" rev-parse v0.2.0)
tc 0.1.0
check "tag_commit: a lightweight tag's commit" '[ $RC = 0 ] && [ "$OUT" = "$A" ]'
tc v0.2.0
check "tag_commit: an annotated tag is followed to its commit, not the tag object" '[ $RC = 0 ] && [ "$OUT" = "$B" ] && [ "$B" != "$B_TAG" ]'
tag_origin 0.3.0 "$C" annotated
tc 0.3.0
check "tag_commit: an annotated release tag made by hand on GITHUB_SHA is GITHUB_SHA" '[ "$OUT" = "$C" ]'
untag_origin 0.3.0
tc 0.3.0
check "tag_commit: nothing for a tag that is not there" '[ $RC = 0 ] && [ -z "$OUT" ]'
tc 0.1.0 "$(printf '1111\trefs/tags/10.1.0\n2222\trefs/tags/0.1.0.1\n3333\trefs/tags/v0.1.0\n4444\trefs/tags/0x1y0\n5555\trefs/heads/0.1.0')"
check "tag_commit: only refs/tags/<tag> itself counts (no longer names, no v, no dots as wildcards)" '[ -z "$OUT" ]'
tc 0.4.0 "$(printf 'cccc\trefs/tags/0.4.0^{}\naaaa\trefs/tags/0.4.0\n')"
check "tag_commit: the peeled line wins wherever it is" '[ "$OUT" = cccc ]'

echo "# $pass passed, $fail failed"
[ "$fail" = 0 ]
