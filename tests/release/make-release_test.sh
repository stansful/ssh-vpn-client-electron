#!/usr/bin/env bash
# Tests of scripts/make-release.sh on the host: throwaway repositories, each a clone of its own local bare
# "origin", in a temp dir (TMPDIR). The script runs from a directory outside the repository, under $TEST_BASH
# (default: bash from PATH, /bin/bash 3.2 on macOS). git reads only this test's config (HOME is the temp dir).
# A port of Shadow for OpenWrt's tests/unit/release/make-release_test.sh, with package.json and
# package-lock.json in place of build/VERSION.
#
#   tests/release/make-release_test.sh          KEEP=1 keeps the temp dir
#
# Prints 'ok <name>' / 'not ok <name>: <why>' and exits non-zero on a failure.
# The conditions of check() are eval'd when it runs: single quotes on purpose, and the variables they read are
# set outside them.
# shellcheck disable=SC2016,SC2034
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TREE="$(cd "$HERE/../.." && pwd -P)"
BASH_BIN="${TEST_BASH:-bash}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/make-release-test.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
if [ -z "${KEEP:-}" ]; then trap 'rm -rf "$WORK"' EXIT; else echo "# work dir: $WORK"; fi

export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
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
# check <name> <condition (eval'd)>: on failure prints the script's output
check() {
	if eval "$2"; then ok "$1"; else nok "$1" "rc=$RC; condition: $2; output:
$OUT"; fi
}
has() { case $OUT in *"$1"*) return 0 ;; esac; return 1; }

echo "# scripts/make-release.sh under $("$BASH_BIN" -c 'echo "bash $BASH_VERSION"'), $(git --version), node $(node --version)"

# write_package <dir> <version> [lock version]: package.json and package-lock.json as npm writes them
write_package() {
	cat >"$1/package.json" <<EOF
{
  "name": "seed",
  "version": "$2",
  "private": true,
  "scripts": {
    "test": "echo \"version: 1.0.0\""
  }
}
EOF
	cat >"$1/package-lock.json" <<EOF
{
  "name": "seed",
  "version": "${3:-$2}",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "seed",
      "version": "${3:-$2}"
    },
    "node_modules/dep": {
      "version": "1.0.0"
    }
  }
}
EOF
}
# copy_scripts <dir>: the release scripts of this tree
copy_scripts() {
	mkdir -p "$1/scripts/lib"
	cp "$TREE/scripts/make-release.sh" "$1/scripts/"
	cp "$TREE/scripts/lib/version.sh" "$TREE/scripts/lib/package-version.mjs" "$1/scripts/lib/"
}

# --- the template: origin.git with master (version 0.1.0, the scripts) and the tag 0.1.0 on its first commit
TPL="$WORK/tpl"
mkdir -p "$TPL/seed"
copy_scripts "$TPL/seed"
write_package "$TPL/seed" 0.1.0
echo readme >"$TPL/seed/README"
printf 'release/\n' >"$TPL/seed/.gitignore"
(
	set -e
	cd "$TPL/seed"
	git -c init.defaultBranch=master init -q .
	git symbolic-ref HEAD refs/heads/master
	git add -A
	git commit -q -m init
	git tag 0.1.0
	echo more >>README
	git commit -q -am 'fix: something'
	git init -q --bare "$TPL/origin.git"
	git -C "$TPL/origin.git" symbolic-ref HEAD refs/heads/master
	git push -q "$TPL/origin.git" master 0.1.0
) || {
	echo "not ok the test fixture could not be built"
	exit 1
}

# new_case <name>: CASE/origin.git (a copy of the template's) and its clone REPO
new_case() {
	CASE="$WORK/$1"
	mkdir -p "$CASE"
	cp -R "$TPL/origin.git" "$CASE/origin.git"
	git clone -q "$CASE/origin.git" "$CASE/repo"
	REPO="$CASE/repo"
}
# mr <stdin (printf %b)> [args...]: make-release.sh of REPO, run from WORK; sets OUT and RC
mr() {
	local input="$1"
	shift
	OUT="$(cd "$WORK" && printf '%b' "$input" | "$BASH_BIN" "$REPO/scripts/make-release.sh" "$@" 2>&1)"
	RC=$?
}
g() { git -C "$REPO" "$@"; }
# ver: "<package.json> <package-lock.json> <packages[""]>" of REPO's tree
ver() {
	node -e 'const fs = require("fs"); const p = JSON.parse(fs.readFileSync(process.argv[1] + "/package.json", "utf8"));
		const l = JSON.parse(fs.readFileSync(process.argv[1] + "/package-lock.json", "utf8"));
		console.log([p.version, l.version, l.packages[""].version].join(" "))' "$REPO"
}
count() { g rev-list --count HEAD; }
subject() { g log -1 --format=%s; }
head_files() { g show --name-only --format= HEAD | tr '\n' ' '; }
# head_numstat: "<added> <removed> <file>" per file of HEAD, one line
head_numstat() { g show --numstat --format= HEAD | tr '\t\n' '  '; }
origin_ref() { git -C "$CASE/origin.git" rev-parse -q --verify "refs/heads/$1"; }
all_tags() { { g tag -l && git -C "$CASE/origin.git" tag -l; } | LC_ALL=C sort | tr '\n' ' '; }
clean() { [ -z "$(g status --porcelain)" ]; }

# --- Enter takes the suggestion
new_case enter
before=$(count) head=$(g rev-parse HEAD) origin=$(origin_ref master) tags=$(all_tags)
mr '\n\n\n'
check "prints the current version" 'has "Текущая версия (package.json): 0.1.0"'
check "prints the last release tag" 'has "Последний релизный тег:        0.1.0"'
check "suggests the next patch version" 'has "Новая версия [0.1.1]: "'
check "Enter takes 0.1.1, Enter commits (run from outside the repository)" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ]'
check "...exactly one new commit, on the old HEAD" '[ "$(count)" = $((before + 1)) ] && [ "$(g rev-parse HEAD^)" = "$head" ]'
check "...named 'feat: release - version 0.1.1'" '[ "$(subject)" = "feat: release - version 0.1.1" ]'
check "...with package.json and package-lock.json only" '[ "$(head_files)" = "package-lock.json package.json " ] && clean'
check "...changing only the version lines (one in package.json, two in package-lock.json)" '[ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ]'
check "...a script's text that looks like a version is left alone" 'g show HEAD:package.json | grep -qF "\"test\": \"echo \\\"version: 1.0.0\\\"\""'
check "...shows the diff" 'has "-  \"version\": \"0.1.0\"," && has "+  \"version\": \"0.1.1\","'
check "...never pushes and never asks to: origin and tags untouched" '[ "$(origin_ref master)" = "$origin" ] && [ "$(all_tags)" = "$tags" ] && ! has "Запуш" && ! has "запуш" && ! has "git push"'

# --- the prompt asks again after a refused version
new_case reask
before=$(count)
mr '0.0.9\n0.1.0\n1.2\nv0.2.0\n01.2.3\n0.2.0-rc1\n  0.2.0  \ny\nn\n'
check "prompt: a lower version is refused" 'has "версия 0.0.9 не выше текущей 0.1.0. Введите другую версию."'
check "prompt: an existing tag is refused" 'has "тег 0.1.0 уже есть: версия 0.1.0 уже выпускалась. Введите другую версию."'
check "prompt: a malformed version is refused" 'has "«1.2» — не версия X.Y.Z" && has "«01.2.3» — не версия X.Y.Z" && has "«0.2.0-rc1» — не версия X.Y.Z"'
check "prompt: a version with v is refused" 'has "«v0.2.0»: нужна версия без «v», например 0.2.0"'
check "prompt: then 0.2.0 (spaces trimmed) is committed" '[ $RC = 0 ] && [ "$(ver)" = "0.2.0 0.2.0 0.2.0" ] && [ "$(count)" = $((before + 1)) ] && [ "$(subject)" = "feat: release - version 0.2.0" ]'

# --- end of input at the prompt
new_case eof
before=$(count)
mr 'abc\n'
check "end of input at the prompt changes nothing" '[ $RC = 1 ] && has "ввод прерван, ничего не изменено" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'

# --- refused versions given as the argument
new_case refuse
before=$(count)
for c in "0.0.9|версия 0.0.9 не выше текущей 0.1.0" "0.1.0|тег 0.1.0 уже есть" "1.2|«1.2» — не версия X.Y.Z" \
	"1.2.3.4|не версия X.Y.Z" "v0.2.0|нужна версия без «v»" "01.2.3|не версия X.Y.Z" "1.02.3|не версия X.Y.Z" \
	"0.2.0-rc1|не версия X.Y.Z" " 0.2.0|не версия X.Y.Z" "|версия не указана"; do
	v=${c%%|*} want=${c#*|}
	mr '' --yes "$v"
	check "argument '$v' is refused: $want" '[ $RC = 1 ] && has "Ошибка: " && has "$want" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
done

# --- tags: local only, origin only, a legacy vX.Y.Z on origin
new_case tags
g tag 0.5.0
git clone -q "$CASE/origin.git" "$CASE/other"
git -C "$CASE/other" tag 0.7.0
git -C "$CASE/other" tag -a v0.8.0 -m legacy
git -C "$CASE/other" push -q origin 0.7.0 v0.8.0
before=$(count) origin=$(origin_ref master)
mr '' --yes 0.5.0
check "a local tag is refused" '[ $RC = 1 ] && has "тег 0.5.0 уже есть"'
mr '' --yes 0.7.0
check "a tag only on origin is refused" '[ $RC = 1 ] && has "тег 0.7.0 уже есть"'
mr '' --yes 0.8.0
check "a legacy tag v0.8.0 on origin is refused for 0.8.0" '[ $RC = 1 ] && has "тег v0.8.0 уже есть"'
mr '' --yes 0.6.0
check "a version below the highest tag is refused" '[ $RC = 1 ] && has "версия 0.6.0 не выше последнего релизного тега v0.8.0"'
check "...nothing changed" '[ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
mr ''
check "the last tag and the suggestion come from all tags" 'has "Последний релизный тег:        v0.8.0" && has "Новая версия [0.8.1]: " && [ $RC = 1 ]'
mr '' --yes
check "--yes takes the suggested 0.8.1 and commits without a question" '[ $RC = 0 ] && [ "$(ver)" = "0.8.1 0.8.1 0.8.1" ] && [ "$(subject)" = "feat: release - version 0.8.1" ] && [ "$(count)" = $((before + 1)) ]'
check "--yes does not push" '[ "$(origin_ref master)" = "$origin" ] && ! has "Запуш"'

# --- a dirty tree
new_case dirty
before=$(count)
echo change >>"$REPO/README"
mr '' --yes 0.2.0
check "a modified file is refused" '[ $RC = 1 ] && has "есть незакоммиченные изменения" && has "README" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ]'
check "...and stays modified" '[ "$(g status --porcelain)" = " M README" ]'
g checkout -q -- README
echo new >"$REPO/newfile"
g add newfile
mr '' --yes 0.2.0
check "a staged file is refused" '[ $RC = 1 ] && has "есть незакоммиченные изменения" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ]'
g reset -q
mr '' --yes 0.2.0
check "an untracked file is only a warning, and stays out of the commit" '[ $RC = 0 ] && has "есть файлы не в git" && has "  newfile" && [ "$(head_files)" = "package-lock.json package.json " ] && [ "$(g status --porcelain)" = "?? newfile" ]'

# --- package-lock.json
new_case stalelock
write_package "$REPO" 0.1.0 0.0.9
g commit -q -am 'chore: a stale lock'
mr '' --yes 0.1.1
check "a stale package-lock.json is a warning, and the commit sets the new version in both files" '[ $RC = 0 ] && has "в package-lock.json версия 0.0.9 / 0.0.9, а в package.json 0.1.0" && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(head_files)" = "package-lock.json package.json " ]'
new_case indent4
node -e 'const fs = require("fs"); for (const f of ["package.json", "package-lock.json"]) {
	const p = process.argv[1] + "/" + f; fs.writeFileSync(p, JSON.stringify(JSON.parse(fs.readFileSync(p, "utf8")), null, 4) + "\n"); }' "$REPO"
g commit -q -am 'chore: four spaces'
mr '' --yes 0.1.1
check "four-space files keep their indent: only the version lines change" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ] && g show HEAD:package.json | grep -q "^    \"version\": \"0.1.1\",$"'
new_case crlf
node -e 'const fs = require("fs"); const p = process.argv[1] + "/package.json"; fs.writeFileSync(p, fs.readFileSync(p, "utf8").replace(/\n/g, "\r\n"));' "$REPO"
g commit -q -am 'chore: CRLF'
mr '' --yes 0.1.1
check "a CRLF package.json stays CRLF: only its version line changes" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ] && [ "$(g show HEAD:package.json | grep -c "$(printf "\r")$")" = 8 ] && [ "$(g show HEAD:package.json | wc -l | tr -d " ")" = 8 ]'
new_case compact
printf '{"name":"seed","version":"0.1.0","private":true}\n' >"$REPO/package.json"
g commit -q -am 'chore: one line'
before=$(count)
mr '' --yes 0.1.1
check "a package.json npm would not write is refused, nothing changes" '[ $RC = 1 ] && has "package.json записан не так, как его пишет npm" && has "версия не записана" && [ "$(count)" = "$before" ] && clean && [ "$(g show HEAD:package.json)" = "$(cat "$REPO/package.json")" ]'
new_case noeol
printf '%s' "$(cat "$REPO/package-lock.json")" >"$REPO/package-lock.json"
g commit -q -am 'chore: no final newline'
mr '' --yes 0.1.1
check "a lock without the final newline keeps it that way" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ] && [ "$(tail -c 1 "$REPO/package-lock.json")" = "}" ]'
new_case badversion
write_package "$REPO" x
g commit -q -am broken
mr '' --yes 0.4.0
check "a malformed version in package.json is refused" '[ $RC = 1 ] && has "в package.json версия «x», а не X.Y.Z"'
new_case untracked
g rm -q --cached package-lock.json
g commit -q -m 'chore: lock out of git'
mr '' --yes 0.1.1
check "a package-lock.json that is not in git is refused" '[ $RC = 1 ] && has "package-lock.json не в git"'

# --- git hooks: they run on the commit's own index, so what a pre-commit hook stages lands in the commit
# hook <commands>: REPO's pre-commit hook
hook() {
	printf '#!/bin/sh\n%s\n' "$1" >"$REPO/.git/hooks/pre-commit"
	chmod +x "$REPO/.git/hooks/pre-commit"
}
no_verify="git commit --no-verify -m 'feat: release - version 0.1.1' -- package.json package-lock.json"
new_case hooknew
hook 'echo x >>other && git add other'
head=$(g rev-parse HEAD) origin=$(origin_ref master)
mr '' 0.1.1 --yes
check "a hook that stages a new file: the release commit is undone" '[ $RC = 1 ] && has "хук git (pre-commit или другой) изменил релизный коммит" && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(origin_ref master)" = "$origin" ]'
check "...it names the files the commit had and how to commit past the hook" 'has "  package.json" && has "  package-lock.json" && has "  other" && has "$no_verify"'
check "...both files are back in the tree and the index, the hook's file is left untracked" '[ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(g status --porcelain)" = "?? other" ]'
new_case hooktracked
hook 'echo x >>README && git add README'
head=$(g rev-parse HEAD)
mr '' 0.1.1 --yes
check "a hook that stages a tracked file: the commit is undone, the hook's change is left unstaged" '[ $RC = 1 ] && has "  README" && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(g status --porcelain)" = " M README" ]'
new_case hookversion
hook 'sed "s/0\.1\.1/9.9.9/" package.json >p.tmp && mv p.tmp package.json && git add package.json'
head=$(g rev-parse HEAD)
mr '' 0.1.1 --yes
check "a hook that rewrites the version in package.json: the commit is undone" '[ $RC = 1 ] && has "изменил релизный коммит" && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && clean'
new_case hookformat
hook 'node -e "const fs = require(\"fs\"); fs.writeFileSync(\"package-lock.json\", JSON.stringify(JSON.parse(fs.readFileSync(\"package-lock.json\", \"utf8\"))) + \"\\n\")" && git add package-lock.json'
head=$(g rev-parse HEAD)
mr '' 0.1.1 --yes
check "a hook that reformats package-lock.json (same version): the commit is undone" '[ $RC = 1 ] && has "изменил релизный коммит" && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && clean'
new_case hookfail
hook 'exit 1'
head=$(g rev-parse HEAD)
mr '' 0.1.1 --yes
check "a failing hook: no commit, both files are back" '[ $RC = 1 ] && has "git commit не удался, package.json и package-lock.json возвращены" && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && clean'
new_case hookok
hook 'git add package.json package-lock.json'
before=$(count)
mr '' 0.1.1 --yes
check "a hook that stages only the two files unchanged keeps the release commit" '[ $RC = 0 ] && [ "$(count)" = $((before + 1)) ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && [ "$(head_files)" = "package-lock.json package.json " ] && clean'

# --- at the confirmation: a signal, a file edited meanwhile (the script runs in the background, its stdin a FIFO)
# mr_bg <args...>: make-release.sh of REPO in the background, stdin the FIFO CASE/in held open on fd 3; sets PID
mr_bg() {
	rm -f "$CASE/in" "$CASE/out"
	mkfifo "$CASE/in"
	(cd "$WORK" && exec "$BASH_BIN" "$REPO/scripts/make-release.sh" "$@" <"$CASE/in" >"$CASE/out" 2>&1) &
	PID=$!
	exec 3>"$CASE/in"
	# a script that ended early must fail a check, not kill this test with SIGPIPE on the next write to fd 3
	trap '' PIPE
}
# prompted: waits until the script asks to commit (at most 30 s: it only waits for the script to get there)
prompted() {
	local i=0
	until grep -qF '[Y/n] ' "$CASE/out" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -le 300 ] || return 1
		sleep 0.1
	done
}
# mr_end: closes its stdin (a script still reading gets EOF), waits for it; sets RC and OUT
mr_end() {
	exec 3>&-
	wait "$PID"
	RC=$?
	trap - PIPE
	OUT="$(cat "$CASE/out")"
}
new_case sigterm
before=$(count)
mr_bg 0.1.1
if prompted; then kill -TERM "$PID"; else echo "x" >&3; fi
mr_end
check "SIGTERM at the confirmation: both files back, no commit, exit 130" '[ $RC = 130 ] && has "Прервано: package.json и package-lock.json возвращены, коммита нет." && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
new_case editwhileasked
mr_bg 0.1.1
if prompted; then printf '\n' >>"$REPO/package-lock.json"; fi
echo y >&3
mr_end
check "a file edited while the question waits stays out of the commit, and stays edited" '[ $RC = 0 ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && [ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ] && [ "$(g status --porcelain)" = " M package-lock.json" ]'
for answer in y n; do
	new_case "pulled-$answer"
	git clone -q "$CASE/origin.git" "$CASE/other"
	echo upstream >>"$CASE/other/README"
	git -C "$CASE/other" commit -q -am 'fix: upstream'
	git -C "$CASE/other" push -q origin master
	g fetch -q origin
	mr_bg 0.1.1
	if prompted; then g pull -q --ff-only origin master; fi
	pulled=$(g rev-parse HEAD)
	echo "$answer" >&3
	mr_end
	check "a pull while the question waits, then '$answer': no commit, the pulled branch is kept, the tree clean" '[ $RC = 1 ] && has "HEAD сдвинулся" && [ "$(g rev-parse HEAD)" = "$pulled" ] && [ "$(subject)" = "fix: upstream" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && clean'
done
# post-commit hook: says it runs, then waits for the test's go-ahead (at most 30 s)
new_case sigpostcommit
printf '#!/bin/sh\ntouch "%s/hook-ran"\ni=0\nwhile [ ! -e "%s/hook-go" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done\n' "$CASE" "$CASE" >"$REPO/.git/hooks/post-commit"
chmod +x "$REPO/.git/hooks/post-commit"
head=$(g rev-parse HEAD)
mr_bg 0.1.1 --yes
i=0
until [ -e "$CASE/hook-ran" ] || [ $i -ge 300 ]; do
	sleep 0.1
	i=$((i + 1))
done
kill -TERM "$PID"
touch "$CASE/hook-go"
mr_end
check "SIGTERM while git commit is still running (its post-commit hook): the commit made is undone" '[ $RC = 130 ] && has "Прервано: package.json и package-lock.json возвращены, коммита нет." && [ "$(g rev-parse HEAD)" = "$head" ] && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && clean'

# --- any other failure after the version is written undoes it too: a git that fails one command (PATH shim)
mkdir -p "$WORK/shim"
cat >"$WORK/shim/git" <<EOF
#!/bin/sh
for a; do [ "\$a" != "\${GIT_FAIL:-}" ] || { echo "shim: git \$* failed" >&2; exit 1; }; done
exec "$(command -v git)" "\$@"
EOF
chmod +x "$WORK/shim/git"
new_case setefail
before=$(count)
PATH="$WORK/shim:$PATH" GIT_FAIL=diff-index mr '' --yes 0.1.1
check "a failing command after the version is written (set -e): both files back, no commit" '[ $RC = 1 ] && has "Ошибка: скрипт прервался (код 1): package.json и package-lock.json возвращены, коммита нет." && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
new_case orderfile
printf 'package.json\npackage-lock.json\n' >"$REPO/.git/order"
g config diff.orderFile .git/order
mr '' --yes 0.1.1
check "diff.orderFile does not make the check refuse a correct commit" '[ $RC = 0 ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && clean'
new_case extdiff
g config diff.external false
mr '' --yes 0.1.1
check "a failing external diff only spoils the shown diff, not the release" '[ $RC = 0 ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && clean'

# --- line ends under git's conversion, a lock that already has the version, a held index lock
for attrs in "config core.autocrlf input" "attributes * text=auto"; do
	new_case "crlf-${attrs%% *}"
	node -e 'const fs = require("fs"); for (const f of ["package.json", "package-lock.json"]) { const p = process.argv[1] + "/" + f;
		fs.writeFileSync(p, fs.readFileSync(p, "utf8").replace(/\n/g, "\r\n")); }' "$REPO"
	g commit -q -am 'chore: CRLF'
	case $attrs in
	config*) g config core.autocrlf input ;;
	*)
		echo "${attrs#attributes }" >"$REPO/.gitattributes"
		g add .gitattributes
		g commit -q -m 'chore: attributes'
		;;
	esac
	mr '' --yes 0.1.1
	check "CRLF files with $attrs: committed as they were written" '[ $RC = 0 ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && [ "$(head_numstat)" = "2 2 package-lock.json 1 1 package.json " ] && [ "$(g show HEAD:package.json | grep -c "$(printf "\r")$")" = 8 ] && clean'
done
new_case lockahead
write_package "$REPO" 0.1.0 0.1.1
g commit -q -am 'chore: a lock ahead'
mr '' --yes 0.1.1
check "a lock that already has the new version: the commit changes package.json only" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(head_files)" = "package.json " ] && clean'
new_case indexlock
touch "$REPO/.git/index.lock"
before=$(count)
mr '' --yes 0.1.1
rm -f "$REPO/.git/index.lock"
check "a held index lock: no commit, both files back from the copies, git's state named" '[ $RC = 1 ] && has "git add не удался, package.json и package-lock.json возвращены" && has "индекс не сброшен" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'

# --- no push, ever
new_case nopush
origin=$(origin_ref master) tags=$(all_tags)
mr '\n\nд\n'
check "the commit stays local: no push question, origin and tags untouched" '[ $RC = 0 ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && [ "$(origin_ref master)" = "$origin" ] && [ "$(all_tags)" = "$tags" ] && ! has "Запуш"'
mr '' 0.1.2 --push
check "--push is not an option" '[ $RC = 2 ] && has "неизвестный параметр --push"'

# --- the confirmation, --no-commit, options
new_case decline
before=$(count)
mr '0.1.1\nn\n'
check "a declined commit puts both files back" '[ $RC = 1 ] && has "Отменено" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
mr '0.1.1\n'
check "end of input at the confirmation puts both files back" '[ $RC = 1 ] && has "ввод прерван, package.json и package-lock.json возвращены" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ] && [ "$(count)" = "$before" ] && clean'
new_case nocommit
before=$(count)
mr '' 0.1.1 --no-commit
check "--no-commit writes both files and commits nothing" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(count)" = "$before" ] && [ "$(g status --porcelain | tr "\n" " ")" = " M package-lock.json  M package.json " ] && has "--no-commit"'
check "...and says how to commit them" 'has "git commit -m '"'"'feat: release - version 0.1.1'"'"' -- package.json package-lock.json"'
mr '' --bogus
check "an unknown option is a usage error" '[ $RC = 2 ] && has "неизвестный параметр --bogus"'
mr '' 0.1.1 0.1.2
check "two versions are a usage error" '[ $RC = 2 ]'
mr '' --help
check "--help prints the usage" '[ $RC = 0 ] && has "scripts/make-release.sh [X.Y.Z] [--yes] [--no-commit]"'

# --- branches
new_case branch
g checkout -q -b feature
origin=$(origin_ref master)
mr '' 0.1.1 --yes
check "another branch: a warning, then the commit on that branch" '[ $RC = 0 ] && has "вы на ветке feature, а релиз выходит из ветки по умолчанию master" && [ "$(g symbolic-ref --short HEAD)" = feature ] && [ "$(subject)" = "feat: release - version 0.1.1" ] && [ "$(origin_ref master)" = "$origin" ]'
new_case detached
g checkout -q --detach
mr '' 0.1.1 --yes
check "a detached HEAD is refused" '[ $RC = 1 ] && has "detached HEAD" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ]'
new_case behind
git clone -q "$CASE/origin.git" "$CASE/other"
echo other >>"$CASE/other/README"
git -C "$CASE/other" commit -q -am 'fix: other'
git -C "$CASE/other" push -q origin master
g fetch -q origin
origin=$(origin_ref master)
mr '' 0.1.1 --yes
check "a branch behind origin: a warning to pull first, the commit is still made locally" '[ $RC = 0 ] && has "ветка master отстаёт от origin/master на 1" && has "сначала git pull" && [ "$(origin_ref master)" = "$origin" ] && [ "$(subject)" = "feat: release - version 0.1.1" ]'

# --- no origin, no repository, the current version
new_case noorigin
g remote remove origin
before=$(count)
mr '' --yes
check "without origin: local tags count, the commit is made" '[ $RC = 0 ] && [ "$(ver)" = "0.1.1 0.1.1 0.1.1" ] && [ "$(count)" = $((before + 1)) ]'
new_case ahead
write_package "$REPO" 0.3.0
g commit -q -am 'feat: release - version 0.3.0'
mr ''
check "a version above every tag: says it is not released yet and suggests the next patch" 'has "Тега 0.3.0 ещё нет" && has "Новая версия [0.3.1]: "'
mkdir -p "$WORK/plain"
copy_scripts "$WORK/plain"
write_package "$WORK/plain" 0.1.0
REPO="$WORK/plain"
mr '' 0.1.1 --yes
check "outside a git repository it is refused" '[ $RC = 1 ] && has "не git-репозиторий" && [ "$(ver)" = "0.1.0 0.1.0 0.1.0" ]'

echo "# $pass passed, $fail failed"
[ "$fail" = 0 ]
