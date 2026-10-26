#!/usr/bin/env bash
# Prints the notes of release $VERSION, Russian first and then English: which file is for which system, the
# install notes in the README, and the commit subjects since the previous release tag (the highest X.Y.Z or
# vX.Y.Z tag in the history of $GITHUB_SHA other than $VERSION), newest first, without merges and without the
# release commits of scripts/make-release.sh.
#
# Env: GH_REPO or GITHUB_REPOSITORY (owner/repo), GITHUB_SHA (default HEAD), VERSION (default: package.json's,
# read with Node.js). Reads the tags and the history of this checkout (release.yml fetches them all).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
# shellcheck source=scripts/lib/version.sh
. "$ROOT/scripts/lib/version.sh"

repo="${GH_REPO:-${GITHUB_REPOSITORY:?}}"
sha="${GITHUB_SHA:-HEAD}"
VERSION="${VERSION:-$(node "$ROOT/scripts/lib/package-version.mjs" get)}"
version_valid "$VERSION" || {
	echo "release-notes: «${VERSION}» is not X.Y.Z" >&2
	exit 1
}

prev="$(git -C "$ROOT" tag --merged "$sha" | highest_tag "$VERSION")"
prev=${prev#* }
changes="$(git -C "$ROOT" log --no-merges --max-count=200 --pretty=format:'- %s' "${prev:+$prev..}$sha" |
	{ grep -v '^- feat: release - version [0-9]' || true; })"
f="shadow-ssh-$VERSION"

cat <<EOF
Shadow $VERSION для Windows, macOS и Linux. Скачайте файл для своей системы:

Shadow $VERSION for Windows, macOS and Linux. Download the file for your system:

| Система / System | x64 | arm64 |
| --- | --- | --- |
| Windows 10/11 (portable) | \`$f-windows-portable-x64.exe\` | \`$f-windows-portable-arm64.exe\` |
| macOS | \`$f-macos-dmg-x64.dmg\` (Intel) | \`$f-macos-dmg-arm64.dmg\` (Apple Silicon) |
| Linux | \`$f-linux-portable-x86_64.AppImage\`, \`$f-linux-package-amd64.deb\` | \`$f-linux-portable-arm64.AppImage\`, \`$f-linux-package-arm64.deb\` |

Первый запуск неподписанной сборки и обновление: [README](https://github.com/$repo#установка) · First start of an unsigned build and updates: [README.en.md](https://github.com/$repo/blob/HEAD/README.en.md#install)

Изменения${prev:+ с $prev} / Changes${prev:+ since $prev}:

${changes:-- только новая версия / version bump only}
EOF
