#!/usr/bin/env bash
# Prepares a release: shows the current version ("version" in package.json) and the last release tag, asks for the
# new version (Enter takes the next patch version), checks that it is higher than the current version and every
# release tag (local ones and origin's), writes it to package.json and package-lock.json (scripts/lib/
# package-version.mjs: "version" in both and packages[""].version, nothing else) and commits only those two files as
# "feat: release - version X.Y.Z". It never pushes: the release starts when that commit reaches master on GitHub
# (.github/workflows/release.yml: the checks, the build and the release X.Y.Z). No tags here: GitHub creates the
# tag X.Y.Z when the workflow publishes the release (docs/DEVELOPMENT.md, "Release").
# A port of Shadow for OpenWrt's scripts/make-release.sh (stansful/ssh-vpn-client-luci-app-shadow-ucode).
#
#   scripts/make-release.sh [X.Y.Z] [--yes] [--no-commit]
#
# Runs from any directory; bash 3.2 (macOS) or 5 (Linux), BSD or GNU tools, git and Node.js. Messages are in
# Russian.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/.." && pwd -P)"
# shellcheck source=scripts/lib/version.sh
. "$HERE/lib/version.sh"

usage() {
	cat <<'EOF'
Готовит релиз Shadow: новая версия в package.json и package-lock.json и коммит «feat: release - version X.Y.Z».
Релиз X.Y.Z выходит, когда этот коммит оказывается в master на GitHub.

  scripts/make-release.sh [X.Y.Z] [--yes] [--no-commit]

  X.Y.Z         новая версия; без неё скрипт покажет текущую и спросит (Enter — следующая патч-версия)
  -y, --yes     без вопросов: версия — следующая патч-версия (если не указана), коммит без подтверждения
  --no-commit   только записать версию в package.json и package-lock.json, без коммита
  -h, --help    эта справка

Версия — X.Y.Z без ведущих нулей и без «v», выше текущей и всех релизных тегов (свои и в origin).
Теги скрипт не ставит: тег X.Y.Z создаёт GitHub при публикации релиза.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'Внимание: %s\n' "$*" >&2; }
die() {
	printf 'Ошибка: %s\n' "$*" >&2
	exit 1
}
usage_error() {
	printf 'Ошибка: %s\n\n' "$*" >&2
	usage >&2
	exit 2
}
yes_answer() {
	case $1 in
	y | Y | yes | Yes | YES | д | Д | да | Да | ДА) return 0 ;;
	*) return 1 ;;
	esac
}
trim() {
	local s="$1"
	s=${s#"${s%%[![:space:]]*}"}
	s=${s%"${s##*[![:space:]]}"}
	printf '%s' "$s"
}

new='' have_new='' yes='' commit=1
while [ $# -gt 0 ]; do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	-y | --yes) yes=1 ;;
	--no-commit) commit= ;;
	-*) usage_error "неизвестный параметр $1" ;;
	*)
		[ -z "$have_new" ] || usage_error "версия указана дважды: $new и $1"
		new=$1 have_new=1
		;;
	esac
	shift
done

# --- the repository
command -v git >/dev/null 2>&1 || die "нужен git."
command -v node >/dev/null 2>&1 || die "нужен Node.js (версию в package.json читает и пишет scripts/lib/package-version.mjs)."
top="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" ||
	die "$ROOT — не git-репозиторий. Сначала git init, первый коммит и git remote add origin <url>."
[ "$(cd "$top" && pwd -P)" = "$ROOT" ] || die "$ROOT — не корень git-репозитория (корень: $top)."
cd "$ROOT"
git rev-parse -q --verify HEAD >/dev/null || die "в репозитории ещё нет коммитов: сначала закоммитьте проект."
branch="$(git symbolic-ref -q --short HEAD)" ||
	die "HEAD не на ветке (detached HEAD): переключитесь на ветку, например: git switch master."
for f in package.json package-lock.json; do
	git ls-files --error-unmatch "$f" >/dev/null 2>&1 || die "$f не в git: закоммитьте его."
done

dirty="$(git status --porcelain --untracked-files=no)"
if [ -n "$dirty" ]; then
	printf 'Ошибка: есть незакоммиченные изменения (рабочее дерево или индекс):\n%s\n' "$dirty" >&2
	printf 'Закоммитьте их или уберите и запустите снова: в релизный коммит входят только package.json и package-lock.json.\n' >&2
	exit 1
fi
untracked="$(git ls-files --others --exclude-standard)"
if [ -n "$untracked" ]; then
	warn "есть файлы не в git, в релиз они не попадут:"
	printf '%s\n' "$untracked" | sed -n '1,10s/^/  /p' >&2
	[ "$(printf '%s\n' "$untracked" | wc -l | tr -d ' ')" -le 10 ] || printf '  …\n' >&2
fi

has_origin=
git remote get-url origin >/dev/null 2>&1 && has_origin=1

# The default branch: origin's HEAD, else master or main (origin's or local). release.yml releases from master.
default=
if ref="$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null)"; then
	default=${ref#origin/}
else
	for b in master main; do
		if git show-ref -q --verify "refs/remotes/origin/$b" || git show-ref -q --verify "refs/heads/$b"; then
			default=$b
			break
		fi
	done
fi
if [ -z "$default" ]; then
	warn "не удалось определить ветку по умолчанию; релиз выходит только из неё."
elif [ "$branch" != "$default" ]; then
	warn "вы на ветке $branch, а релиз выходит из ветки по умолчанию $default: этот коммит выпустится только после слияния в $default."
fi
if [ -n "$has_origin" ] && git show-ref -q --verify "refs/remotes/origin/$branch"; then
	behind="$(git rev-list --count "HEAD..refs/remotes/origin/$branch")"
	[ "$behind" = 0 ] ||
		warn "ветка $branch отстаёт от origin/$branch на $behind коммит(ов) (по последнему fetch): сначала git pull."
fi

# --- versions
current="$(node "$HERE/lib/package-version.mjs" get)" || die "не удалось прочитать версию из package.json."
version_valid "$current" ||
	die "в package.json версия «$current», а не X.Y.Z: исправьте её вручную (и в package-lock.json) и закоммитьте."
if ! lock_problem="$(node "$HERE/lib/package-version.mjs" check 2>&1)"; then
	warn "${lock_problem#Ошибка: }"
	warn "релизный коммит запишет новую версию в оба файла."
fi

tags="$(git tag -l)"
if [ -n "$has_origin" ]; then
	if remote="$(GIT_TERMINAL_PROMPT=0 git ls-remote --tags origin)"; then
		tags="$tags
$remote"
	else
		warn "не удалось прочитать теги origin ($(git remote get-url origin)): сравниваю только с локальными тегами."
	fi
fi
highest="$(printf '%s\n' "$tags" | highest_tag)"
highest_version=${highest%% *}
last_tag=${highest#* }

say "Текущая версия (package.json): $current"
if [ -n "$highest" ]; then
	say "Последний релизный тег:        $last_tag"
else
	say "Релизных тегов пока нет."
fi
if [ -z "$highest" ] || version_gt "$current" "$highest_version"; then
	say "Тега $current ещё нет: если коммит с этой версией уже в ветке по умолчанию, релиз $current выйдет и без новой версии."
fi
base=$current
[ -z "$highest" ] || ! version_gt "$highest_version" "$base" || base=$highest_version
suggested="$(version_next_patch "$base")"

# check_version <v>: prints why v cannot be the new version, and fails
check_version() {
	local v="$1" t
	if [ -z "$v" ]; then
		echo "версия не указана"
		return 1
	fi
	if ! version_valid "$v"; then
		case $v in
		v[0-9]* | V[0-9]*) echo "«$v»: нужна версия без «v», например ${v#?}" ;;
		*) echo "«$v» — не версия X.Y.Z (три числа без ведущих нулей, например $suggested)" ;;
		esac
		return 1
	fi
	t="$(printf '%s\n' "$tags" | tag_of_version "$v")"
	if [ -n "$t" ]; then
		echo "тег $t уже есть: версия $v уже выпускалась"
		return 1
	fi
	if ! version_gt "$v" "$current"; then
		echo "версия $v не выше текущей $current"
		return 1
	fi
	if [ -n "$highest" ] && ! version_gt "$v" "$highest_version"; then
		echo "версия $v не выше последнего релизного тега $last_tag"
		return 1
	fi
}

if [ -n "$have_new" ]; then
	reason="$(check_version "$new")" || die "$reason."
elif [ -n "$yes" ]; then
	new=$suggested
	say "Новая версия: $new"
else
	while :; do
		printf 'Новая версия [%s]: ' "$suggested"
		if ! IFS= read -r answer; then
			echo
			die "ввод прерван, ничего не изменено."
		fi
		answer="$(trim "$answer")"
		[ -n "$answer" ] || answer=$suggested
		if reason="$(check_version "$answer")"; then
			new=$answer
			break
		fi
		printf '  %s. Введите другую версию.\n' "$reason" >&2
	done
fi

# --- package.json, package-lock.json and the commit
message="feat: release - version $new"
parent="$(git rev-parse HEAD)"
# The two files as they are in HEAD (the tree is clean). restore() copies them back, so it works without the index
# lock and whatever IFS is when a trap fires (inside `IFS= read`, say).
saved="$(mktemp -d "${TMPDIR:-/tmp}/make-release.XXXXXX")"
cp package.json package-lock.json "$saved/"
finished='' left=''
# our_commit: whether HEAD is this run's release commit (on $parent, with its message)
our_commit() {
	[ "$(git rev-parse -q --verify 'HEAD^' 2>/dev/null)" = "$parent" ] &&
		[ "$(git log -1 --format=%s 2>/dev/null)" = "$message" ]
}
# restore: undoes this run's commit (that one only: a HEAD someone else moved is left alone), unstages what this run
# staged and puts both files back as HEAD has them; what it could not do goes to `left` and is said
restore() {
	finished=1 left=''
	if [ "$(git rev-parse -q --verify HEAD)" != "$parent" ]; then
		if ! our_commit; then
			warn "HEAD сдвинулся, пока скрипт работал (git pull или коммит в другом терминале); ветку скрипт не трогал."
		elif ! git reset -q --soft "$parent"; then
			left="релизный коммит $(git rev-parse --short HEAD) остался: отмените его сами (git reset --soft $parent)"
		fi
	fi
	git reset -q 2>/dev/null || warn "индекс не сброшен (git reset не удался): проверьте git status."
	if [ "$(git rev-parse -q --verify HEAD)" = "$parent" ]; then
		cp "$saved/package.json" "$saved/package-lock.json" .
	else
		git checkout -q HEAD -- package.json package-lock.json 2>/dev/null ||
			warn "package.json и package-lock.json не взяты из HEAD: проверьте git status."
	fi
	[ -z "$left" ] || warn "$left."
}
# restored: what restore did, for the closing message
restored() {
	if [ -z "$left" ]; then
		echo "package.json и package-lock.json возвращены, коммита нет"
	else
		echo "вернуть всё не удалось (см. выше)"
	fi
}
# Any exit before the end (a failed command under set -e, a closed stdout) undoes the run as well; while restore
# runs, a second Ctrl-C cannot cut it short.
on_exit() {
	local rc=$?
	trap '' INT TERM HUP PIPE
	if [ -z "$finished" ]; then
		restore
		printf 'Ошибка: скрипт прервался (код %s): %s.\n' "$rc" "$(restored)" >&2 || true
	fi
	rm -rf "$saved"
	exit "$rc"
}
# a signal after the end (the commit made and checked, or --no-commit's files written) undoes nothing
on_signal() {
	trap '' INT TERM HUP PIPE
	if [ -z "$finished" ]; then
		restore
		printf '\nПрервано: %s.\n' "$(restored)" >&2 || true
	fi
	exit 130
}
trap on_exit EXIT
trap on_signal INT TERM HUP PIPE
if ! node "$HERE/lib/package-version.mjs" set "$new"; then
	restore
	die "версия не записана, $(restored)."
fi

if [ -z "$commit" ]; then
	finished=1
	git --no-pager diff --no-ext-diff --no-textconv -- package.json package-lock.json || true
	say "Версия $new записана в package.json и package-lock.json. Коммит не создан (--no-commit). Закоммитьте только эти файлы:"
	say "  git commit -m '$message' -- package.json package-lock.json"
	exit 0
fi
# What the commit must hold, fixed before the question: the two files as package-version.mjs wrote them, staged
# (git add applies the line-end rules the commit applies), and which of them changed (a lock that already had the
# new version stays as it is; plumbing, so no diff.orderFile reorders the list). The commit is made from the index,
# so a file edited while the question waits stays out of it.
if ! git add -- package.json package-lock.json; then
	restore
	die "git add не удался, $(restored)."
fi
want_files="$(git diff-index --cached --name-only HEAD)"
want_pkg="$(git rev-parse :package.json)" want_lock="$(git rev-parse :package-lock.json)"
git --no-pager diff --no-ext-diff --no-textconv --cached || true
if [ -z "$yes" ]; then
	printf 'Закоммитить package.json и package-lock.json как «%s»? [Y/n] ' "$message"
	if ! IFS= read -r answer; then
		echo
		restore
		die "ввод прерван, $(restored)."
	fi
	answer="$(trim "$answer")"
	if [ -n "$answer" ] && ! yes_answer "$answer"; then
		restore
		say "Отменено: $(restored)."
		exit 1
	fi
fi
if [ "$(git rev-parse HEAD)" != "$parent" ]; then
	restore
	die "HEAD сдвинулся, пока скрипт ждал ответа: $(restored). Запустите скрипт снова."
fi
if ! git commit -q -m "$message"; then
	restore
	die "git commit не удался, $(restored)."
fi
# git hooks (pre-commit and the like) run on the commit's index: whatever one stages lands in the commit.
# The release commit is the version edits and nothing else, on $parent, or it is undone.
changed="$(git diff-tree -r --name-only "$parent" HEAD)"
if ! our_commit || [ "$changed" != "$want_files" ] || [ "$(git rev-parse -q --verify HEAD:package.json)" != "$want_pkg" ] ||
	[ "$(git rev-parse -q --verify HEAD:package-lock.json)" != "$want_lock" ]; then
	restore
	{
		printf 'Ошибка: хук git (pre-commit или другой) изменил релизный коммит, а в нём должны быть только package.json и package-lock.json с версией %s. В коммит попало:\n' "$new"
		printf '%s\n' "$changed" | sed 's/^/  /'
		printf 'Коммит отменён: %s; что хук поменял в других файлах, там и осталось (git status).\n' "$(restored)"
		printf 'Поправьте хук или закоммитьте в обход хуков: scripts/make-release.sh %s --no-commit, затем\n' "$new"
		printf "  git commit --no-verify -m '%s' -- package.json package-lock.json\n" "$message"
	} >&2
	exit 1
fi
finished=1
say "Коммит $(git rev-parse --short HEAD): $message"
