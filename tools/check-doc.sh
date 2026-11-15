#!/bin/sh
# Fail when the regenerated API documentation differs from what is about to be
# committed. ipparse/doc/ is tracked so beginners can read it without LDoc, so
# it must stay in sync with the sources / config.ld.
#
# The reference is the INDEX, not HEAD: the normal flow is `make -C ipparse doc`
# then `git add ipparse/doc ipparse-X.Y-Z.rockspec`, so the regenerated pages
# are already staged when the pre-commit hook runs.
set -eu

repo=$(git rev-parse --show-toplevel)
cd "$repo"

stale() {
	echo "doc périmée : lancez make -C ipparse doc puis git add ipparse/doc" >&2
}

make -C ipparse doc

# Unstaged change to a tracked page: the worktree is not what will be committed.
if ! git diff --quiet -- ipparse/doc; then
	stale
	git diff --stat -- ipparse/doc >&2
	exit 1
fi

# New page (module added to config.ld) that nobody staged.
untracked=$(git ls-files --others --exclude-standard -- ipparse/doc)
if [ -n "$untracked" ]; then
	stale
	echo "$untracked" >&2
	exit 1
fi
