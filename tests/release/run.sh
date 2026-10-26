#!/usr/bin/env bash
# Runs the tests of the release scripts on the host (tests/release/*_test.sh): scripts/make-release.sh,
# scripts/build-release.sh, .github/scripts/release-state.sh and release-notes.sh against throwaway git
# repositories and stubs in TMPDIR. Needs bash 3.2+, git and Node.js; TEST_BASH=<bash> runs the tests and the
# scripts under that bash (macOS: /bin/bash is 3.2). CI runs it under bash 5 (ci.yml lint) and 3.2 (ci.yml quality).
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
fail=0
for t in "$HERE"/*_test.sh; do
	echo "# ${t##*/}"
	"${TEST_BASH:-bash}" "$t" || fail=1
done
exit "$fail"
