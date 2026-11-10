--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_pack_compat.moon
-- Byte-for-byte equivalence tests for the LuaJIT pack fallback.

util = require "ipparse.lib.util"
{:test} = util
pack_compat = require "ipparse.lib.pack_compat"
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

-- More than eight arguments exercises the generic vararg path.
test "pack_compat: >B x10 more than 8 args", ->
  got = pack ">B B B B B B B B B B", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
  expected = from_hex "0102030405060708090a"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Padding byte between integers.
test "pack_compat: >H x H", ->
  got = pack ">H x H", 1, 2
  expected = from_hex "0001000002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- String options in the middle of integer fields.
test "pack_compat: >H c2 H", ->
  got = pack ">H c2 H", 1, "ab", 2
  expected = from_hex "000161620002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >H z H", ->
  got = pack ">H z H", 1, "ab", 2
  expected = from_hex "00016162000002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >H s2 H", ->
  got = pack ">H s2 H", 1, "ab", 2
  expected = from_hex "0001000261620002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Signed 32-bit negative value wraps to two's complement.
test "pack_compat: >i4 negative", ->
  got = pack ">i4", -2
  expected = from_hex "fffffffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 64-bit little-endian value above the 32-bit range keeps its high word.
test "pack_compat: <I8 above 32-bit range", ->
  got = pack "<I8", 0x100000000
  expected = from_hex "0000000001000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Empty format yields an empty string.
test "pack_compat: empty format", ->
  got = pack ""
  assert got == "", "got: #{got}"

-- ─── 64-bit signed and unsigned values ──────────────────────────────────────

unpack = pack_compat.unpack or string.unpack

-- -2 as a signed 64-bit value is 0xff..fe in two's complement.
test "pack_compat: >i8 negative bytes", ->
  got = pack ">i8", -2
  expected = from_hex "fffffffffffffffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- -1 as a signed 64-bit value is all ones in two's complement.
test "pack_compat: <i8 negative one bytes", ->
  got = pack "<i8", -1
  expected = from_hex "ffffffffffffffff"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- -(2^53), exactly representable as a double, keeps its low 64-bit pattern.
test "pack_compat: >i8 negative 2^53 bytes", ->
  got = pack ">i8", -9007199254740992
  expected = from_hex "ffe0000000000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: <I8 above 32-bit range bytes", ->
  got = pack "<I8", 0x100000000
  expected = from_hex "0000000001000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- "=" selects the native byte order: little-endian on the x86/ARM hosts used
-- by the test suite (and the documented assumption of the pure-Lua fallback).
test "pack_compat: =I4 native little-endian", ->
  got = pack "=I4", 0x01020304
  expected = from_hex "04030201"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >i8 negative round-trip", ->
  v, pos = unpack ">i8", pack(">i8", -2)
  assert v == -2, "got: #{v}"
  assert pos == 9, "pos: #{pos}"

-- ─── Truncated input must raise, as native string.unpack does ───────────────

test "pack_compat: unpack B on empty string raises", ->
  ok, err = pcall unpack, "B", "", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack c8 on 3-byte string raises", ->
  ok, err = pcall unpack, "c8", "abc", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack >s1 with truncated body raises", ->
  ok, err = pcall unpack, ">s1", "\005ab", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack full-width controls still work", ->
  assert unpack("B", "a", 1) == 97, "B on 'a'"
  assert unpack("c3", "abc", 1) == "abc", "c3 on 'abc'"
  assert unpack(">s1", "\002ab", 1) == "ab", "s1 on '\\002ab'"
  assert unpack("c0", "", 1) == "", "c0 on ''"

util.summary "pack_compat"
