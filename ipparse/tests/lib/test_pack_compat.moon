--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_pack_compat.moon
-- Byte-for-byte equivalence tests for the LuaJIT pack fallback.

util = require "ipparse.lib.util"
{:test} = util
pack_compat = require "ipparse.lib.pack_compat_lib"
pack = pack_compat.pack or string.pack
-- Native string.pack rejects the two fallback-only behaviours tested below.
is_fallback = pack != string.pack

from_hex = (h) -> h\gsub "..", (cc) -> string.char tonumber cc, 16

-- Big-endian header-like mix of 16-bit and 8-bit fields.
test "pack_compat: >H B B H H H H", ->
  got = pack ">H B B H H H H", 1, 2, 3, 4, 5, 6, 7
  expected = from_hex "000102030004000500060007"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Big-endian mix with a 4-byte integer and a 2-byte-prefixed string.
test "pack_compat: >H H I4 s2", ->
  got = pack ">H H I4 s2", 1, 1, 300, "abcd"
  expected = from_hex "000100010000012c000461626364"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Little-endian 4-byte integer.
test "pack_compat: <I4", ->
  got = pack "<I4", 0x01020304
  expected = from_hex "04030201"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Signed 16-bit negative value wraps to two's complement.
test "pack_compat: >i2 negative", ->
  got = pack ">i2", -2
  expected = from_hex "fffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Fixed-width string shorter than the field is NUL-padded.
test "pack_compat: >c4 short", ->
  got = pack ">c4", "ab"
  expected = from_hex "61620000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

if is_fallback
  -- Fixed-width string longer than the field is truncated.
  test "pack_compat: >c4 long", ->
    got = pack ">c4", "abcdef"
    expected = from_hex "61626364"
    assert got == expected, "got: #{got}\nexp: #{expected}"

-- NUL-terminated string gets a trailing \0.
test "pack_compat: z", ->
  got = pack "z", "hello"
  expected = from_hex "68656c6c6f00"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Padding emits one NUL byte.
test "pack_compat: x", ->
  got = pack "x"
  expected = from_hex "00"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 3-byte big-endian unsigned integer.
test "pack_compat: >I3", ->
  got = pack ">I3", 0x010203
  expected = from_hex "010203"
  assert got == expected, "got: #{got}\nexp: #{expected}"

if is_fallback
  -- uint8 keeps the low byte of out-of-range values (300 % 256 == 44).
  test "pack_compat: B 300 wraps", ->
    got = pack "B", 300
    expected = from_hex "2c"
    assert got == expected, "got: #{got}\nexp: #{expected}"

util.summary "pack_compat"
