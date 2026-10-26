# shellcheck shell=bash
# Release versions, shared by scripts/make-release.sh, scripts/build-release.sh and .github/scripts/*.sh
# (sourced, not run). A version is X.Y.Z: three decimal numbers without leading zeros (0 itself is fine). It is
# "version" in package.json (and its two copies in package-lock.json, scripts/lib/package-version.mjs), the
# release's tag and the release's file names; the in-app updater reads it from the tag of /releases/latest
# (src/core/update/github-app-update.ts, which also takes vX.Y.Z). Tags vX.Y.Z count as version X.Y.Z.
# The same file as in Shadow for OpenWrt (stansful/ssh-vpn-client-luci-app-shadow-ucode), apart from this header.
# bash 3.2 (macOS) and 5 (Linux); no sort -V, which BSD sort lacks.

VERSION_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# version_valid <s>: whether s is X.Y.Z
version_valid() {
	[[ $1 =~ $VERSION_RE ]]
}

# version_cmp <a> <b>: prints -1, 0 or 1 for a < b, a = b, a > b (both valid). Numbers of any length: without
# leading zeros the longer number is the larger one, and numbers of one length compare as strings.
version_cmp() {
	local a="$1." b="$2." x y
	while [ -n "$a" ]; do
		x=${a%%.*} y=${b%%.*}
		a=${a#*.} b=${b#*.}
		[ "$x" = "$y" ] && continue
		if [ ${#x} -gt ${#y} ] || { [ ${#x} -eq ${#y} ] && [[ $x > $y ]]; }; then
			echo 1
		else
			echo -1
		fi
		return 0
	done
	echo 0
}

# version_gt <a> <b>: whether a > b
version_gt() {
	[ "$(version_cmp "$1" "$2")" = 1 ]
}

# version_next_patch <X.Y.Z>: prints X.Y.(Z+1)
version_next_patch() {
	local z=${1##*.}
	echo "${1%.*}.$((z + 1))"
}

# release_tags: reads tag names, or the lines of `git ls-remote --tags` (refs/tags/<tag>, <tag>^{}), on stdin
# and prints "<X.Y.Z> <tag>" for every release tag (X.Y.Z or vX.Y.Z), once per tag
release_tags() {
	local line ref v seen=' '
	while IFS= read -r line || [ -n "$line" ]; do
		ref=${line##*[[:space:]]}
		ref=${ref#refs/tags/}
		ref=${ref%'^{}'}
		v=${ref#v}
		version_valid "$v" || continue
		case $seen in *" $ref "*) continue ;; esac
		seen="$seen$ref "
		echo "$v $ref"
	done
}

# highest_tag [skip]: reads what release_tags reads and prints "<X.Y.Z> <tag>" of the highest release tag other
# than the tag named skip; nothing when there is none
highest_tag() {
	local skip="${1:-}" v t best='' best_tag=''
	while read -r v t; do
		[ "$t" = "$skip" ] && continue
		if [ -z "$best" ] || version_gt "$v" "$best"; then
			best=$v best_tag=$t
		fi
	done < <(release_tags)
	[ -z "$best" ] || echo "$best $best_tag"
}

# tag_of_version <X.Y.Z>: reads what release_tags reads and prints the first tag of that version (X.Y.Z or
# vX.Y.Z); nothing when there is none
tag_of_version() {
	local v t
	while read -r v t; do
		if [ "$v" = "$1" ]; then
			echo "$t"
			return 0
		fi
	done < <(release_tags)
}

# tag_commit <tag>: reads the lines of `git ls-remote --tags <remote>` (every tag: given a pattern, ls-remote leaves
# out an annotated tag's peeled line) on stdin and prints the commit refs/tags/<tag> is on: the peeled "<tag>^{}"
# line of an annotated tag, else the tag's own line; nothing when there is no such tag. release-state.sh and
# release.yml's publish job both resolve the tag with it.
tag_commit() {
	awk -v ref="refs/tags/$1" '
		$2 == ref { sha = $1 }
		$2 == ref "^{}" { peeled = $1 }
		END { if (peeled != "") print peeled; else if (sha != "") print sha }'
}
