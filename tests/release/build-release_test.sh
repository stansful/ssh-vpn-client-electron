#!/usr/bin/env bash
# Tests of scripts/build-release.sh on the host, without building anything: a throwaway tree with the script,
# package.json and package-lock.json, and stubs of npm, go and uname first on PATH. The npm stub writes the release
# files that npm run build:prod would, or fails the way hdiutil does on hosted macOS runners. Runs the script under
# $TEST_BASH (default: bash).
#
#   tests/release/build-release_test.sh          KEEP=1 keeps the temp dir
#
# Prints 'ok <name>' / 'not ok <name>: <why>' and exits non-zero on a failure.
# The conditions of check() are eval'd when it runs: single quotes on purpose, and the variables they read are
# set outside them.
# shellcheck disable=SC2016,SC2034
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TREE="$(cd "$HERE/../.." && pwd -P)"
BASH_BIN="${TEST_BASH:-bash}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/build-release-test.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
if [ -z "${KEEP:-}" ]; then trap 'rm -rf "$WORK"' EXIT; else echo "# work dir: $WORK"; fi

export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
# CI sets GITHUB_ACTIONS; the cases below set it where they need it
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GITHUB_ACTIONS GH_TOKEN GITHUB_TOKEN CSC_IDENTITY_AUTO_DISCOVERY
export BUILD_RELEASE_RETRY_DELAY=0
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
$OUT
calls:
$(cat "$WORK/calls.log" 2>/dev/null)"; fi
}
has() { case $OUT in *"$1"*) return 0 ;; esac; return 1; }
called() { grep -qxF -- "$1" "$WORK/calls.log"; }
# calls: the commands the stubs ran, but `go version`, joined by |
calls() { cut -d'|' -f1 "$WORK/calls.log" | sed 's/ *$//' | grep -vx 'go version' | tr '\n' '|'; }

# --- the stubs; STUB_* variables steer them
mkdir -p "$WORK/bin"
cat >"$WORK/bin/npm" <<'EOF'
#!/bin/sh
# npm stub, run in the tree's root: logs "<args> | <the env electron-builder reads>" and fakes the commands.
#   STUB_BUILD=hdiutil|broken  npm run build:prod fails after the Windows files, like hdiutil, or otherwise
#   STUB_RETRY=broken          npm run pack:prod-mac fails
#   STUB_MISSING / STUB_EMPTY / STUB_BIG=<suffix>  that file is left out / empty / 160 MiB + 1 byte
#   STUB_EXTRA=<name>          one more file in release/
#   STUB_ZSTD=1                the AppImage warning of a build without the zstd-19 wrapper
#   STUB_FAIL=<args>           that command fails
printf '%s | GH_TOKEN=%s GITHUB_TOKEN=%s CSC=%s\n' "$*" "${GH_TOKEN-unset}" "${GITHUB_TOKEN-unset}" \
	"${CSC_IDENTITY_AUTO_DISCOVERY-unset}" >>"$STUB_LOG"
[ "${STUB_FAIL:-}" != "$*" ] || { echo "stub: $* failed"; exit 1; }
v=$(node -p 'require("./package.json").version')
put() {
	mkdir -p release
	for s; do
		f="release/shadow-ssh-$v-$s"
		if [ "$s" = "${STUB_MISSING:-}" ]; then continue
		elif [ "$s" = "${STUB_EMPTY:-}" ]; then : >"$f"
		elif [ "$s" = "${STUB_BIG:-}" ]; then dd if=/dev/zero of="$f" bs=1 count=0 seek=167772161 2>/dev/null
		else printf 'built %s\n' "$s" >"$f"
		fi
	done
}
WIN="windows-portable-x64.exe windows-portable-arm64.exe"
MAC="macos-dmg-x64.dmg macos-dmg-arm64.dmg"
LINUX="linux-portable-x86_64.AppImage linux-portable-arm64.AppImage linux-package-amd64.deb linux-package-arm64.deb"
case "$*" in
--version) echo 11.6.2 ;;
"run wintun:download") touch .wintun ;;
"run wintun:ensure") [ -e .wintun ] || exit 1 ;;
"run build:prod")
	case ${STUB_BUILD:-ok} in
	hdiutil)
		put $WIN
		mkdir -p release/mac release/mac-arm64
		: >"release/shadow-ssh-$v-macos-dmg-x64.dmg"
		echo "  ⨯ hdiutil process failed ERR_ELECTRON_BUILDER_CANNOT_EXECUTE"
		echo "hdiutil: create failed - Resource busy"
		exit 1
		;;
	broken)
		echo "  ⨯ cannot find module"
		exit 1
		;;
	esac
	put $WIN $MAC $LINUX
	[ -z "${STUB_EXTRA:-}" ] || printf x >"release/$STUB_EXTRA"
	[ -z "${STUB_ZSTD:-}" ] || echo "  • AppImage uses the default zstd level"
	;;
"run pack:prod-mac")
	[ "${STUB_RETRY:-}" != broken ] || exit 1
	# the first attempt's macOS output is gone
	[ ! -e release/mac ] && [ ! -e release/mac-arm64 ] && [ ! -e "release/shadow-ssh-$v-macos-dmg-x64.dmg" ] || {
		echo "stub: stale macOS output"
		exit 1
	}
	put $MAC
	;;
"run pack:prod-linux") put $LINUX ;;
esac
exit 0
EOF
cat >"$WORK/bin/go" <<'EOF'
#!/bin/sh
# go stub: logs its arguments; the pinned wintun digest test passes, unless STUB_DIGESTS=skip or fail
printf 'go %s\n' "$*" >>"$STUB_LOG"
[ "${STUB_FAIL:-}" != "go $*" ] || exit 1
[ "$1" != version ] || echo "go version go1.25.3 darwin/arm64"
case "$*" in
*TestPinnedWintunDigestsMatchTheFetchedDLLs*)
	case ${STUB_DIGESTS:-pass} in
	skip) printf -- '--- SKIP: TestPinnedWintunDigestsMatchTheFetchedDLLs (0.00s)\nok\n' ;;
	fail)
		printf -- '--- FAIL: TestPinnedWintunDigestsMatchTheFetchedDLLs (0.00s)\nFAIL\n'
		exit 1
		;;
	*) printf -- '--- PASS: TestPinnedWintunDigestsMatchTheFetchedDLLs (0.00s)\nok\n' ;;
	esac
	;;
esac
EOF
printf '#!/bin/sh\necho "${STUB_UNAME:-Darwin}"\n' >"$WORK/bin/uname"
chmod +x "$WORK/bin/npm" "$WORK/bin/go" "$WORK/bin/uname"
export STUB_LOG="$WORK/calls.log"

# new_tree [version] [lock version]: DIR with the scripts, the package files and node_modules
n=0
new_tree() {
	n=$((n + 1))
	DIR="$WORK/tree$n"
	mkdir -p "$DIR/scripts/lib" "$DIR/node_modules"
	cp "$TREE/scripts/build-release.sh" "$DIR/scripts/"
	cp "$TREE/scripts/lib/version.sh" "$TREE/scripts/lib/package-version.mjs" "$DIR/scripts/lib/"
	printf '{\n  "name": "seed",\n  "version": "%s"\n}\n' "${1:-1.2.3}" >"$DIR/package.json"
	printf '{\n  "name": "seed",\n  "version": "%s",\n  "lockfileVersion": 3,\n  "packages": {\n    "": {\n      "version": "%s"\n    }\n  }\n}\n' \
		"${2:-${1:-1.2.3}}" "${2:-${1:-1.2.3}}" >"$DIR/package-lock.json"
}
# br [VAR=value...] [-- args...]: build-release.sh of DIR, run from WORK with the stubs; sets OUT and RC
br() {
	local envs=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do
		envs+=("$1")
		shift
	done
	[ $# -eq 0 ] || shift
	: >"$WORK/calls.log"
	OUT="$(cd "$WORK" && env PATH="$WORK/bin:$PATH" ${envs[@]+"${envs[@]}"} "$BASH_BIN" "$DIR/scripts/build-release.sh" "$@" 2>&1)"
	RC=$?
}
V=1.2.3
ALL="windows-portable-x64.exe windows-portable-arm64.exe macos-dmg-x64.dmg macos-dmg-arm64.dmg linux-portable-x86_64.AppImage linux-portable-arm64.AppImage linux-package-amd64.deb linux-package-arm64.deb"
# listed: every file of ALL is in the output with its size and its SHA-256
listed() {
	local s f
	for s in $ALL; do
		f="$DIR/release/shadow-ssh-$V-$s"
		[ -f "$f" ] || return 1
		has "$(wc -c <"$f" | tr -d ' ')  shadow-ssh-$V-$s" || return 1
		has "$( (cd "$DIR/release" && shasum -a 256 "shadow-ssh-$V-$s"))" || return 1
	done
}

# the wintun steps of every build, as calls() lists them
WINTUN='run wintun:download|run wintun:ensure|go -C native/service-go test -count=1 -v -run ^TestPinnedWintunDigestsMatchTheFetchedDLLs$ ./internal/tun|'

echo "# scripts/build-release.sh under $("$BASH_BIN" -c 'echo "bash $BASH_VERSION"'), node $(node --version)"

# --- a build
new_tree
br
check "builds with npm run build:prod and lists the eight files with sizes and SHA-256" '[ $RC = 0 ] && has "== Сборка 1.2.3: npm run build:prod" && has "Релиз 1.2.3: $DIR/release" && has "SHA-256:" && listed'
check "...prints the version and the tools" 'has "== Shadow 1.2.3: node $(node --version), npm 11.6.2, go1.25.3 darwin/arm64"'
check "...runs only wintun.dll's download, check and pinned digests before it, no tests without --test" '[ "$(calls)" = "--version|${WINTUN}run build:prod|" ]'
check "...electron-builder gets no GitHub token and looks for no signing identity" 'called "run build:prod | GH_TOKEN= GITHUB_TOKEN= CSC=false"'
check "...no warnings" '! has "Внимание" && ! has "::warning::"'
br GH_TOKEN=secret GITHUB_TOKEN=secret CSC_IDENTITY_AUTO_DISCOVERY=true
check "a token in the environment never reaches the build; CSC_IDENTITY_AUTO_DISCOVERY=true is kept" '[ $RC = 0 ] && called "run build:prod | GH_TOKEN= GITHUB_TOKEN= CSC=true"'

# --- --test, wintun
new_tree
br -- --test
check "--test runs typecheck, lint, Vitest and go test before the build" '[ $RC = 0 ] && [ "$(calls)" = "--version|run typecheck|run lint|test|go -C native/service-go test ./...|${WINTUN}run build:prod|" ]'
br STUB_FAIL="run lint" -- --test
check "...a failing check stops before the build" '[ $RC = 1 ] && has "npm run lint не прошёл" && ! called "run build:prod | GH_TOKEN= GITHUB_TOKEN= CSC=false"'
br STUB_FAIL="go -C native/service-go test ./..." -- --test
check "...go test too" '[ $RC = 1 ] && has "go test не прошёл" && ! grep -q "^run build:prod" "$WORK/calls.log"'
new_tree
br STUB_FAIL="run wintun:download"
check "a failed wintun.dll download stops before the build" '[ $RC = 1 ] && has "не удалось скачать wintun.dll" && ! grep -q "^run build:prod" "$WORK/calls.log"'
br STUB_DIGESTS=skip
check "a skipped pinned-digest test stops before the build, with its output" '[ $RC = 1 ] && has "проверка SHA-256 wintun.dll не прошла (тест пропущен?)" && has "--- SKIP: TestPinnedWintunDigestsMatchTheFetchedDLLs" && ! grep -q "^run build:prod" "$WORK/calls.log"'
br STUB_DIGESTS=fail GITHUB_ACTIONS=true
check "a failed one too, in Actions with an error annotation" '[ $RC = 1 ] && has "::error::SHA-256 wintun.dll не совпадают с закреплёнными" && has "--- FAIL: TestPinnedWintunDigestsMatchTheFetchedDLLs" && ! grep -q "^run build:prod" "$WORK/calls.log"'

# --- hdiutil
new_tree
br STUB_BUILD=hdiutil
check "hdiutil failed: macOS and Linux are packed once more, then verified and pruned" '[ $RC = 0 ] && [ "$(calls)" = "--version|${WINTUN}run build:prod|run pack:prod-mac|run pack:prod-linux|run verify:prod-artifacts|run release:prune|" ] && listed'
check "...without tokens or a signing identity either" 'called "run pack:prod-mac | GH_TOKEN= GITHUB_TOKEN= CSC=false" && called "run pack:prod-linux | GH_TOKEN= GITHUB_TOKEN= CSC=false"'
check "...says so, outside Actions without an annotation" 'has "Внимание: hdiutil не смог собрать DMG; собираю macOS и Linux ещё раз." && ! has "::warning::"'
new_tree
br STUB_BUILD=hdiutil GITHUB_ACTIONS=true
check "...in Actions with a warning annotation" '[ $RC = 0 ] && has "::warning::hdiutil не смог собрать DMG; собираю macOS и Linux ещё раз."'
new_tree
br STUB_BUILD=hdiutil STUB_RETRY=broken
check "a second failure fails the build" '[ $RC = 1 ] && has "повторная сборка macOS и Linux не прошла" && ! has "Релиз 1.2.3"'
new_tree
br STUB_BUILD=broken
check "any other failure fails at once, no second pass" '[ $RC = 1 ] && has "npm run build:prod не прошёл" && [ "$(calls)" = "--version|${WINTUN}run build:prod|" ]'
new_tree
br STUB_ZSTD=1
check "an AppImage without the zstd-19 wrapper is a warning" '[ $RC = 0 ] && has "AppImage собран без обёртки zstd-19"'

# --- the files
new_tree
br STUB_MISSING=linux-package-arm64.deb
check "a missing file fails the build" '[ $RC = 1 ] && has "в release/ нет shadow-ssh-1.2.3-linux-package-arm64.deb" && ! has "SHA-256:"'
new_tree
br STUB_EXTRA=latest-mac.yml
check "any other file in release/ fails the build" '[ $RC = 1 ] && has "в release/ лишнее: latest-mac.yml"'
new_tree
br STUB_EMPTY=macos-dmg-arm64.dmg
check "an empty file fails the build" '[ $RC = 1 ] && has "release/shadow-ssh-1.2.3-macos-dmg-arm64.dmg — 0 байт"'
new_tree
br STUB_BIG=windows-portable-x64.exe
check "a file above 160 MiB fails the build" '[ $RC = 1 ] && has "release/shadow-ssh-1.2.3-windows-portable-x64.exe — 167772161 байт; встроенное обновление берёт файлы от 1 до 167772160 байт."'

# --- refusals before anything runs
new_tree 1.2
br
check "a malformed version is refused" '[ $RC = 1 ] && has "в package.json версия «1.2», а не X.Y.Z" && ! grep -q "^run" "$WORK/calls.log"'
new_tree 1.2.3 1.2.2
br
check "a stale package-lock.json is refused" '[ $RC = 1 ] && has "в package-lock.json версия 1.2.2 / 1.2.2, а в package.json 1.2.3" && ! grep -q "^run" "$WORK/calls.log"'
new_tree
rmdir "$DIR/node_modules"
br
check "no node_modules: npm ci first" '[ $RC = 1 ] && has "нет node_modules: сначала npm ci"'
new_tree
br STUB_UNAME=Linux
check "not macOS: refused" '[ $RC = 1 ] && has "релиз собирается только на macOS" && ! grep -q "^run" "$WORK/calls.log"'
br -- --out x
check "an unknown option is a usage error" '[ $RC = 2 ] && has "неизвестный параметр --out"'
br -- --help
check "--help prints the usage" '[ $RC = 0 ] && has "scripts/build-release.sh [--test]"'

# --- git
new_tree
(
	set -e
	cd "$DIR"
	git -c init.defaultBranch=master init -q .
	printf 'node_modules/\n/release/\n.wintun\n' >.gitignore
	echo readme >README
	git add -A
	git commit -q -m init
) || echo "not ok the git fixture could not be built"
br
check "a clean checkout: no warning" '[ $RC = 0 ] && ! has "незакоммиченные"'
echo change >>"$DIR/README"
br
check "uncommitted changes: a warning that the build differs from the commit's release" '[ $RC = 0 ] && has "Внимание: есть незакоммиченные изменения — эта сборка не совпадёт с релизом коммита $(git -C "$DIR" rev-parse --short HEAD)."'

echo "# $pass passed, $fail failed"
[ "$fail" = 0 ]
