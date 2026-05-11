--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
{:bin2hex, :hex2bin, :filterascii, :hexdump} = require"ipparse.init"

-- bin2hex and hexdump use string.unpack which is unavailable in LuaJIT 2.x;
-- those tests are omitted.

test "hex2bin converts hex to bytes", ->
  result = hex2bin "ff00"
  assert result == "\xff\x00", "hex2bin failed"

test "hex2bin single byte", ->
  result = hex2bin "ab"
  assert result == "\xab", "hex2bin single byte failed"

test "filterascii replaces non-printable with dot", ->
  result = filterascii "\x01hello\xff"
  assert result == ".hello.", "expected '.hello.', got '#{result}'"

test "filterascii keeps printable chars", ->
  result = filterascii "hello"
  assert result == "hello", "expected 'hello', got '#{result}'"


util.summary "init"
