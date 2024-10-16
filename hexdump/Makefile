# SPDX-FileCopyrightText: (c) 2024 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
# SPDX-License-Identifier: MIT OR GPL-2.0-only

NAME = hexdump
CFLAGS = -O2 -Wall -I/usr/local/include/lunatik
LUA_MODULE_DIR = /lib/modules/lua
LUNATIK_EBPF_INSTALL_PATH = /usr/local/lib/bpf/lunatik


all:
	moonc . || echo "Install MoonScript if you intend to modify sources."

install:
	mkdir ${LUA_MODULE_DIR}/${NAME} || true
	cp --parents `find . -name \*.lua | grep -v config.lua` ${LUA_MODULE_DIR}/${NAME}

uninstall:
	rm -rf ${LUA_MODULE_DIR}/${NAME}

xdp.o: xdp.c vmlinux.h
	clang -target bpf -Wall -O2 -c -g $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f vmlinux.h xdp.o
