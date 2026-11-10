--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
{:bin2hex, :hex2bin, :filterascii, :hexdump, :lbin2hex} = require"ipparse.init"

test "bin2hex converts bytes to hex", ->
  assert bin2hex("\255\000\171") == "ff00ab", "bin2hex failed"

test "hex2bin converts hex to bytes", ->
  result = hex2bin "ff00"
  assert result == "\255\000", "hex2bin failed"

test "hex2bin single byte", ->
  result = hex2bin "ab"
  assert result == "\171", "hex2bin single byte failed"

test "filterascii replaces non-printable with dot", ->
  result = filterascii "\001hello\255"
  assert result == ".hello.", "expected '.hello.', got '#{result}'"

test "filterascii keeps printable chars", ->
  result = filterascii "hello"
  assert result == "hello", "expected 'hello', got '#{result}'"

test "lbin2hex handles a 100-byte string", ->
  result = lbin2hex string.rep "a", 100
  assert #result == 200, "expected 200 hex chars, got #{#result}"

test "lbin2hex handles a 128-byte string", ->
  result = lbin2hex string.rep "a", 128
  assert #result == 256, "expected 256 hex chars, got #{#result}"

test "lbin2hex handles a 200-byte string", ->
  result = lbin2hex string.rep "a", 200
  assert #result == 400, "expected 400 hex chars, got #{#result}"

test "lbin2hex handles the empty string", ->
  result = lbin2hex ""
  assert result == "", "expected '', got '#{result}'"

test "hexdump prints offset and hex for a 16-byte line", ->
  result = hexdump "abcdefghijklmnop", 1, 8, 2
  assert result\sub(1, 6) == "0000: ", "expected '0000: ' prefix, got '#{result\sub(1, 6)}'"
  assert result\find("6162636465666768", 1, true), "expected hex of first bytes in '#{result}'"


util.summary "init"
