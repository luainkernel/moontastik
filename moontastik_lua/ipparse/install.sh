#!/usr/bin/env sh

NAME=ipparse
LUA_MODULE_DIR=/lib/modules/lua

mkdir ${LUA_MODULE_DIR}/${NAME} || true
find . -name \*.lua -exec install -vDm 644 {} ${LUA_MODULE_DIR}/${NAME}/{} \;

