#!/usr/bin/env bash
# Tests of .github/scripts/release-notes.sh on the host: a throwaway repository with release tags, a side branch
# and a merge. Runs the script under $TEST_BASH (default: bash).
# A port of Shadow for OpenWrt's tests/unit/release/release-notes_test.sh.
#
#   tests/release/release-notes_test.sh          KEEP=1 keeps the temp dir
#
# Prints 'ok <name>' / 'not ok <name>: <why>' and exits non-zero on a failure.
# The conditions of check() are eval'd when it runs: single quotes on purpose, and the variables they read are
# set outside them.
# shellcheck disable=SC2016,SC2034
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TREE="$(cd "$HERE/../.." && pwd -P)"
BASH_BIN="${TEST_BASH:-bash}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/release-notes-test.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
if [ -z "${KEEP:-}" ]; then trap 'rm -rf "$WORK"' EXIT; else echo "# work dir: $WORK"; fi

export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GH_REPO GITHUB_REPOSITORY GITHUB_SHA VERSION
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
	if eval "$2"; then ok "$1"; else nok "$1" "rc=$RC; condition: $2; output:
$OUT"; fi
}
line() { printf '%s\n' "$OUT" | grep -qxF -- "$1"; }

# new_repo <dir>: a repository with the scripts and package.json 0.2.0
new_repo() {
	REPO="$1"
	mkdir -p "$REPO/scripts/lib" "$REPO/.github/scripts"
	cp "$TREE/scripts/lib/version.sh" "$TREE/scripts/lib/package-version.mjs" "$REPO/scripts/lib/"
	cp "$TREE/.github/scripts/release-notes.sh" "$REPO/.github/scripts/"
	printf '{\n  "name": "seed",\n  "version": "0.2.0"\n}\n' >"$REPO/package.json"
	git -c init.defaultBranch=master init -q "$REPO"
	git -C "$REPO" symbolic-ref HEAD refs/heads/master
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m 'feat: first'
}
c() { git -C "$REPO" commit -q --allow-empty -m "$1"; }
# rn [VAR=value...]: release-notes.sh of REPO, run from WORK; sets OUT and RC
rn() {
	OUT="$(cd "$WORK" && env GITHUB_REPOSITORY=owner/repo "$@" "$BASH_BIN" "$REPO/.github/scripts/release-notes.sh" 2>&1)"
	RC=$?
}

# v0.0.9 (legacy, annotated) - fix: second (0.1.0) - [side: side work (0.1.5)] - release commit - topic merge - fix: third
new_repo "$WORK/main"
git -C "$REPO" tag -a v0.0.9 -m legacy
c 'fix: second'
git -C "$REPO" tag 0.1.0
git -C "$REPO" checkout -q -b side
c 'side work'
git -C "$REPO" tag 0.1.5
git -C "$REPO" checkout -q master
c 'feat: release - version 0.2.0'
git -C "$REPO" checkout -q -b topic
c 'feat: topic'
git -C "$REPO" checkout -q master
git -C "$REPO" merge -q --no-ff -m 'Merge branch topic' topic
c 'fix: third'

rn
check "Russian first: the version of package.json and the systems" '[ $RC = 0 ] && [ "$(printf "%s\n" "$OUT" | head -n 1)" = "Shadow 0.2.0 для Windows, macOS и Linux. Скачайте файл для своей системы:" ]'
check "then English" 'line "Shadow 0.2.0 for Windows, macOS and Linux. Download the file for your system:"'
check "the eight files of this version, by system and architecture" 'line "| Windows 10/11 (portable) | \`shadow-ssh-0.2.0-windows-portable-x64.exe\` | \`shadow-ssh-0.2.0-windows-portable-arm64.exe\` |" && line "| macOS | \`shadow-ssh-0.2.0-macos-dmg-x64.dmg\` (Intel) | \`shadow-ssh-0.2.0-macos-dmg-arm64.dmg\` (Apple Silicon) |" && line "| Linux | \`shadow-ssh-0.2.0-linux-portable-x86_64.AppImage\`, \`shadow-ssh-0.2.0-linux-package-amd64.deb\` | \`shadow-ssh-0.2.0-linux-portable-arm64.AppImage\`, \`shadow-ssh-0.2.0-linux-package-arm64.deb\` |"'
check "the README links of this repository" 'line "Первый запуск неподписанной сборки и обновление: [README](https://github.com/owner/repo#установка) · First start of an unsigned build and updates: [README.en.md](https://github.com/owner/repo/blob/HEAD/README.en.md#install)"'
check "changes since the previous release tag in the history (0.1.0, not the side branch's 0.1.5)" 'line "Изменения с 0.1.0 / Changes since 0.1.0:"'
check "the commits since then, newest first" '[ "$(printf "%s\n" "$OUT" | grep "^- " | tr "\n" "|")" = "- fix: third|- feat: topic|" ]'
check "...without merges, release commits, older or side commits" '! line "- Merge branch topic" && ! line "- feat: release - version 0.2.0" && ! line "- fix: second" && ! line "- side work"'
git -C "$REPO" tag 0.2.0
rn
check "a tag of the version itself (a retry) is not the previous one" 'line "Изменения с 0.1.0 / Changes since 0.1.0:"'
rn GH_REPO=other/name GITHUB_SHA=0.1.0 VERSION=0.1.0
check "GH_REPO, GITHUB_SHA and VERSION: the history up to that commit, since the legacy tag v0.0.9" 'line "Изменения с v0.0.9 / Changes since v0.0.9:" && line "- fix: second" && ! line "- fix: third" && printf "%s\n" "$OUT" | grep -qF "https://github.com/other/name#установка" && line "Shadow 0.1.0 for Windows, macOS and Linux. Download the file for your system:" && printf "%s\n" "$OUT" | grep -qF "shadow-ssh-0.1.0-macos-dmg-arm64.dmg"'

new_repo "$WORK/first"
c 'fix: a'
rn
check "no release tag yet: every commit" '[ $RC = 0 ] && line "Изменения / Changes:" && line "- fix: a" && line "- feat: first"'
git -C "$REPO" tag 0.1.0
c 'feat: release - version 0.2.0'
rn
check "only a release commit since the last tag" 'line "Изменения с 0.1.0 / Changes since 0.1.0:" && line "- только новая версия / version bump only"'
rn VERSION=v0.2.0
check "a malformed VERSION is refused" '[ $RC = 1 ]'

echo "# $pass passed, $fail failed"
[ "$fail" = 0 ]
