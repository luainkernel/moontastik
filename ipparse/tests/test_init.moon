--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
{:bin2hex, :hex2bin, :filterascii, :hexdump, :lbin2hex, :dump, :need_bytes} = require"ipparse.init"

test "bin2hex converts bytes to hex", ->
  assert bin2hex("\255\000\171") == "ff00ab", "bin2hex failed"

test "hex2bin converts hex to bytes", ->
  result = hex2bin "ff00"
  assert result == "\255\000", "hex2bin failed"

test "hex2bin single byte", ->
  result = hex2bin "ab"
  assert result == "\171", "hex2bin single byte failed"

test "hex2bin returns exactly one value", ->
  n = select "#", hex2bin "00ff"
  assert n == 1, "expected 1 return value, got #{n}"

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

test "bin2hex handles a 4096-byte string", ->
  result = bin2hex string.rep "a", 4096
  assert #result == 8192, "expected 8192 hex chars, got #{#result}"
  assert result == string.rep("61", 4096), "bin2hex content mismatch"

test "bin2hex converts non-printable bytes", ->
  result = bin2hex "\000\010\255"
  assert result == "000aff", "expected '000aff', got '#{result}'"

test "hexdump prints offset and hex for a 16-byte line", ->
  result = hexdump "abcdefghijklmnop", 1, 8, 2
  assert result\sub(1, 6) == "0000: ", "expected '0000: ' prefix, got '#{result\sub(1, 6)}'"
  assert result\find("6162636465666768", 1, true), "expected hex of first bytes in '#{result}'"


test "dump renders sorted key/value pairs", ->
  assert dump({b: 2, a: 1}) == "a: 1, b: 2", "dump mismatch"
  assert dump({}) == "", "empty table should dump as an empty string"

test "need_bytes rejects negative length and bad offset", ->
  assert need_bytes("abc", 1, 0) == true, "zero length at valid offset should pass"
  assert need_bytes("abc", 0, 1) == false, "offset below 1 should fail"
  assert need_bytes("abc", 1, -1) == false, "negative length should fail"
  assert need_bytes("abc", 4, 1) == false, "offset past the end should fail"

test "hexdump pads an incomplete final line", ->
  result = hexdump "abc"
  assert result == "0000: 616263 abc", "unexpected incomplete line: '#{result}'"

test "hexdump honours offset, length, cols and format", ->
  result = hexdump "\001\002\003\004", 2, 2, 1, "%02X"
  assert result == "0001: 0203 ..\n0003: 04 .", "unexpected hexdump: '#{result}'"


util.summary "init"
