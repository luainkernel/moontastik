# SPDX-FileCopyrightText: (c) 2024 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
# SPDX-License-Identifier: MIT OR GPL-2.0-only

NAME = ipparse
LUA_MODULE_DIR = /lib/modules/lua


all:
	moonc .

install:
	mkdir ${LUA_MODULE_DIR}/${NAME} || true
	cp --parents `find . -name \*.lua` ${LUA_MODULE_DIR}/${NAME}

uninstall:
	rm -rf ${LUA_MODULE_DIR}/${NAME}

clean:
	rm ${shell find . -name \*.lua}
