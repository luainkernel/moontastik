# Compile the .moon sources individually: `find` does not follow symlinks,
# so the ipparse/ipparse -> . symlink (needed by the tests) is not walked.
# Passing relative paths keeps the tree under moontastik_lua/ (moonc -t
# only flattens absolute paths).
lua_files:
	find . -type f -name '*.moon' -exec moonc -t moontastik_lua/ {} +
	find . -name install.sh -exec cp {} moontastik_lua/{} \;

zip: lua_files
	zip -r moontastik_lua.zip moontastik_lua && rm -r moontastik_lua

# Enable the versioned hooks: the pre-commit one regenerates/checks
# ipparse/doc/ before a rockspec bump (see tools/check-doc.sh).
hooks:
	git config core.hooksPath .githooks

all:
	$(MAKE) -C ipparse all

install:
	$(MAKE) -C ipparse install

vm-test:
	tools/vmtest/run.sh

vm-smoke:
	tools/vmtest/run.sh --smoke
