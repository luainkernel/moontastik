lua_files:
	moonc -t moontastik_lua/ .
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
