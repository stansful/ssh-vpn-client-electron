#!/usr/bin/env bash
# Builds the release files of the version in package.json exactly as the release workflow does
# (.github/workflows/release.yml runs this script): wintun.dll (npm run wintun:download, which keeps a verified copy
# in .cache, wintun:ensure, and go test against the SHA-256 the helper pins in internal/tun/verify.go), then npm run
# build:prod (the Go helper, the Electron app, electron-builder for every system and both architectures,
# verify:prod-artifacts, release:prune). Hosted macOS runners now and then fail hdiutil with "Resource busy"
# (actions/runner-images#7522) and nothing in electron-builder retries it, so then macOS and Linux are packed once
# more (the Windows files of the first attempt are still in release/). Then release/ must hold exactly the eight
# files the in-app updater looks for (src/core/update/github-app-update.ts), each 1 byte to 160 MiB, which
# release.yml publishes as they are:
#   shadow-ssh-<version>-<suffix> for every suffix in ASSET_SUFFIXES
# Prints the version, the files with their sizes and their SHA-256 sums.
#
#   scripts/build-release.sh [--test]
#
#   --test   first typecheck, lint, Vitest and go test ./... (native/service-go): the core of ci.yml, without its
#            Windows go vet, shellcheck and release-script tests
#
# Needs macOS (the DMGs are made with hdiutil), Node.js with node_modules (npm ci), Go (npm run
# native:build-service, the wintun test) and the network for wintun.dll when .cache has no copy yet. In GitHub
# Actions a failure or warning is also an annotation on the run's page. electron-builder runs without
# GH_TOKEN/GITHUB_TOKEN, so it never publishes anything itself, and without looking for a signing identity
# (CSC_IDENTITY_AUTO_DISCOVERY=false, as in CI; set it to true to sign with the keychain's).
# Env: BUILD_RELEASE_RETRY_DELAY  seconds before the second attempt after hdiutil failed (default 15)
# bash 3.2 (macOS) or 5 (Linux). Messages are in Russian.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/.." && pwd -P)"
# shellcheck source=scripts/lib/version.sh
. "$HERE/lib/version.sh"

# What every release publishes, after "shadow-ssh-<version>-"; release.yml (ASSET_SUFFIXES) publishes exactly these
# and tests/release-assets.test.ts checks both lists against the updater's names.
ASSET_SUFFIXES="windows-portable-x64.exe windows-portable-arm64.exe macos-dmg-x64.dmg macos-dmg-arm64.dmg linux-portable-x86_64.AppImage linux-portable-arm64.AppImage linux-package-amd64.deb linux-package-arm64.deb"
# The updater ignores assets above 160 MiB.
MAX_ASSET_BYTES=167772160

usage() {
	cat <<'EOF'
Собирает файлы релиза версии из package.json так же, как GitHub Actions (release.yml запускает этот скрипт):
npm run build:prod, затем проверка, что в release/ ровно восемь файлов, которые ищет встроенное обновление.

  scripts/build-release.sh [--test]

  --test      сначала npm run typecheck, npm run lint, npm test и go test ./... в native/service-go
  -h, --help  эта справка

Нужны macOS (DMG собирает hdiutil), Node.js с node_modules (npm ci) и Go.
EOF
}
say() { printf '%s\n' "$*"; }
warn() {
	printf 'Внимание: %s\n' "$*" >&2
	# an annotation on the run's summary page
	[ -z "${GITHUB_ACTIONS:-}" ] || printf '::warning::%s\n' "$*"
}
die() {
	printf 'Ошибка: %s\n' "$*" >&2
	[ -z "${GITHUB_ACTIONS:-}" ] || printf '::error::%s\n' "$*"
	exit 1
}
usage_error() {
	printf 'Ошибка: %s\n\n' "$*" >&2
	usage >&2
	exit 2
}
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}
# build <npm args...>: npm for the packaging steps, never publishing and never signing on its own
build() {
	GH_TOKEN='' GITHUB_TOKEN='' CSC_IDENTITY_AUTO_DISCOVERY="${CSC_IDENTITY_AUTO_DISCOVERY:-false}" npm "$@"
}

run_tests=''
while [ $# -gt 0 ]; do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--test) run_tests=1 ;;
	*) usage_error "неизвестный параметр $1" ;;
	esac
	shift
done

cd "$ROOT"
[ "$(uname -s)" = Darwin ] || die "релиз собирается только на macOS: DMG делает hdiutil (в CI — macos-26)."
command -v node >/dev/null 2>&1 || die "нужен Node.js."
command -v npm >/dev/null 2>&1 || die "нужен npm."
command -v go >/dev/null 2>&1 || die "нужен Go: npm run native:build-service собирает им помощник."
[ -d node_modules ] || die "нет node_modules: сначала npm ci."

version="$(node "$HERE/lib/package-version.mjs" get)" || die "не удалось прочитать версию из package.json."
version_valid "$version" || die "в package.json версия «${version}», а не X.Y.Z (без ведущих нулей и «v»)."
node "$HERE/lib/package-version.mjs" check || exit 1

if command -v git >/dev/null 2>&1 && git rev-parse -q --verify HEAD >/dev/null 2>&1 &&
	[ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
	warn "есть незакоммиченные изменения — эта сборка не совпадёт с релизом коммита $(git rev-parse --short HEAD)."
fi
say "== Shadow $version: node $(node --version), npm $(npm --version), $(go version | sed 's/^go version //')"

if [ -n "$run_tests" ]; then
	say "== Тесты: npm run typecheck"
	npm run typecheck || die "npm run typecheck не прошёл."
	say "== Тесты: npm run lint"
	npm run lint || die "npm run lint не прошёл."
	say "== Тесты: npm test"
	npm test || die "npm test не прошёл."
	say "== Тесты: go test ./... (native/service-go)"
	go -C native/service-go test ./... || die "go test не прошёл."
fi

# wintun.dll is not in git, and Windows packaging refuses to run without it. The download replaces whatever DLL is
# in the tree with the pinned release's, and the helper loads only a DLL whose SHA-256 it pins: a wrong pin would
# ship a helper that refuses its own DLL. The test skips without the DLLs, so a skip fails here too.
say "== wintun.dll: npm run wintun:download, wintun:ensure, закреплённые SHA-256 (go test)"
npm run wintun:download || die "не удалось скачать wintun.dll (npm run wintun:download)."
npm run wintun:ensure || die "wintun.dll не годится (npm run wintun:ensure)."
digests="$(go -C native/service-go test -count=1 -v -run '^TestPinnedWintunDigestsMatchTheFetchedDLLs$' ./internal/tun 2>&1)" ||
	{
		printf '%s\n' "$digests" >&2
		die "SHA-256 wintun.dll не совпадают с закреплёнными в native/service-go/internal/tun/verify.go."
	}
case $digests in
*'--- PASS: TestPinnedWintunDigestsMatchTheFetchedDLLs'*) ;;
*)
	printf '%s\n' "$digests" >&2
	die "проверка SHA-256 wintun.dll не прошла (тест пропущен?)."
	;;
esac

log="$(mktemp "${TMPDIR:-/tmp}/build-release.XXXXXX")"
trap 'rm -f "$log"' EXIT

say "== Сборка $version: npm run build:prod"
if ! build run build:prod 2>&1 | tee "$log"; then
	grep -Eq 'hdiutil.*failed|Resource busy' "$log" || die "npm run build:prod не прошёл."
	warn "hdiutil не смог собрать DMG; собираю macOS и Linux ещё раз."
	sync
	sleep "${BUILD_RELEASE_RETRY_DELAY:-15}"
	rm -rf release/mac release/mac-arm64 release/*.dmg
	{
		build run pack:prod-mac && build run pack:prod-linux &&
			npm run verify:prod-artifacts && npm run release:prune
	} 2>&1 | tee -a "$log" || die "повторная сборка macOS и Linux не прошла."
fi
if grep -q 'uses the default zstd level' "$log"; then
	warn "AppImage собран без обёртки zstd-19 и примерно на 10 МБ больше обычного."
fi

# exactly the published files: release:prune leaves nothing else, and the updater takes them as they are
expected='' found=''
for suffix in $ASSET_SUFFIXES; do
	expected="$expected shadow-ssh-$version-$suffix"
done
for f in release/*; do
	[ -e "$f" ] || continue
	found="$found ${f#release/}"
done
for name in $expected; do
	case " $found " in *" $name "*) ;; *) die "в release/ нет $name (есть:${found:- ничего})." ;; esac
done
for name in $found; do
	case " $expected " in *" $name "*) ;; *) die "в release/ лишнее: $name; в релиз идут только$expected." ;; esac
done

say
say "Релиз $version: $ROOT/release"
for name in $expected; do
	[ -f "release/$name" ] || die "release/$name — не файл."
	size="$(wc -c <"release/$name" | tr -d ' ')"
	if [ "$size" -eq 0 ] || [ "$size" -gt "$MAX_ASSET_BYTES" ]; then
		die "release/$name — $size байт; встроенное обновление берёт файлы от 1 до $MAX_ASSET_BYTES байт."
	fi
	printf '  %10s  %s\n' "$size" "$name"
done
say
say "SHA-256:"
cd release
# shellcheck disable=SC2086 # expected is a list of plain file names
sha256 $expected | sed 's/^/  /'
