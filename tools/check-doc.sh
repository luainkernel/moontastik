#!/bin/sh
# Fail when the committed API documentation is not what `make -C ipparse doc`
# would produce. ipparse/doc/ is tracked so beginners can read it without
# LDoc, so it must stay in sync with the sources / config.ld.
set -eu

repo=$(git rev-parse --show-toplevel)
cd "$repo"

make -C ipparse doc

stale=$(git status --porcelain -- ipparse/doc)
if [ -n "$stale" ]; then
	echo "doc périmée : lancez make -C ipparse doc et commitez ipparse/doc" >&2
	echo "$stale" >&2
	exit 1
fi
