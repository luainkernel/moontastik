# SPDX-FileCopyrightText: (c) 2024 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
# SPDX-License-Identifier: MIT OR GPL-2.0-only

NAME = ipparse
LUA_MODULE_DIR = /lib/modules/lua


all:
	moonc `find . -name \*.moon`

install: all install-nobuild

# The *-nobuild targets skip moonc: they reuse .lua files compiled earlier,
# for contexts where the source tree is read-only (e.g. the vmtest VM).
install-nobuild:
	mkdir -p ${LUA_MODULE_DIR}/${NAME}
	cp --parents `find . -name \*.lua` ${LUA_MODULE_DIR}/${NAME}
	cp quic.pcapng ${LUA_MODULE_DIR}/${NAME}/quic.pcapng 2>/dev/null || true
	cp quic_google.pcapng ${LUA_MODULE_DIR}/${NAME}/quic_google.pcapng 2>/dev/null || true

uninstall:
	rm -rf ${LUA_MODULE_DIR}/${NAME}

test: all test-nobuild

test-nobuild:
	cd .. && LUA_PATH="./?.lua;./?/init.lua" luajit ipparse/tests/run_all.lua

example: all
	cd .. && LUA_PATH="./?.lua;./?/init.lua" luajit ipparse/examples/parse_real_quic.lua

test-lunatik: all
	@$(MAKE) install
	@$(MAKE) test-lunatik-run

test-lunatik-nobuild: install-nobuild test-lunatik-run

test-lunatik-run:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: lunatik tests must be run as root (sudo)."; \
		exit 1; \
	fi
	@if ! command -v lunatik >/dev/null 2>&1; then \
		echo "ERROR: lunatik command not found."; \
		exit 1; \
	fi
	@start=$$(dmesg | wc -l); \
	echo "Running kernel Lunatik crypto tests..."; \
	status=0; \
	for test in ipparse/tests/lib/crypto/test_lunatik_kernel_quic_session_e2e ipparse/tests/lib/crypto/test_lunatik_kernel ipparse/tests/lib/crypto/test_lunatik_kernel_quic_simple ipparse/tests/lib/crypto/test_lunatik_kernel_quic_comprehensive ipparse/tests/lib/crypto/test_lunatik_kernel_integration ipparse/tests/lib/crypto/test_lunatik_kernel_crypto_pipeline ipparse/tests/lib/crypto/test_lunatik_kernel_quic_google_capture; do \
		echo "Running $$test..."; \
		if lunatik run "$$test"; then \
			: ; \
		else \
			status=1; \
		fi; \
		lunatik stop "$$test" 2>/dev/null || true; \
		sleep 1; \
	done; \
	echo "----- dmesg (new lines) -----"; \
	dmesg | tail -n +$$((start + 1)); \
	if dmesg | tail -n +$$((start + 1)) | grep -q 'FAIL\|ERROR loading'; then \
		echo "Kernel tests reported failures (see dmesg above)"; \
		status=1; \
	fi; \
	exit $$status

# Only remove .lua files generated from a .moon source (some .lua are hand-written).
clean:
	@for f in `find . -name \*.moon`; do rm -f "$${f%.moon}.lua"; done
