--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_pack_compat_float.moon
-- Floating-point tests for the pack/unpack compatibility layer.
-- Kept in a separate module because the Lua 5.5 kernel runtime has no floats:
-- a single float literal would make the whole chunk fail to compile
-- ("malformed number"), which would also drop the integer tests. This module is
-- therefore NOT listed in test_lunatik_kernel_portable.moon.

util = require "ipparse.lib.util"
{:test} = util
pack_compat = require "ipparse.lib.pack_compat"
pack = pack_compat.pack or string.pack
unpack = pack_compat.unpack or string.unpack

from_hex = (h) -> h\gsub "..", (cc) -> string.char tonumber cc, 16

-- 1.5 is exactly 0x3ff8000000000000; little-endian byte order.
test "pack_compat_float: <d 1.5 bytes", ->
  got = pack "<d", 1.5
  expected = from_hex "000000000000f83f"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- -2.5 is exactly 0xc004000000000000; big-endian byte order.
test "pack_compat_float: >d -2.5 bytes", ->
  got = pack ">d", -2.5
  expected = from_hex "c004000000000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 1.5 is exactly 0x3fc00000 as a 32-bit float; little-endian byte order.
test "pack_compat_float: <f 1.5 bytes", ->
  got = pack "<f", 1.5
  expected = from_hex "0000c03f"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat_float: <d round-trip", ->
  v, pos = unpack "<d", pack("<d", -123.456)
  assert v == -123.456, "got: #{v}"
  assert pos == 9, "pos: #{pos}"

test "pack_compat_float: >d round-trip", ->
  v, pos = unpack ">d", pack(">d", 123.456)
  assert v == 123.456, "got: #{v}"
  assert pos == 9, "pos: #{pos}"

test "pack_compat_float: <f round-trip", ->
  v, pos = unpack "<f", pack("<f", -2.25)
  assert v == -2.25, "got: #{v}"
  assert pos == 5, "pos: #{pos}"

-- IEEE 754 special values: infinities, signed zero, subnormal and NaN.
test "pack_compat_float: <d infinities", ->
  assert unpack("<d", pack("<d", math.huge)) == math.huge
  assert unpack("<d", pack("<d", -math.huge)) == -math.huge

test "pack_compat_float: <d signed zero", ->
  got = pack "<d", -0.0
  expected = from_hex "0000000000000080"
  assert got == expected, "got: #{got}\nexp: #{expected}"
  v = unpack "<d", got
  assert v == 0 and 1 / v < 0, "lost negative zero"

test "pack_compat_float: <d smallest subnormal", ->
  v = 2 ^ -1074
  got = pack "<d", v
  expected = from_hex "0100000000000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"
  assert unpack("<d", got) == v, "subnormal round-trip"

test "pack_compat_float: <d nan", ->
  nan = math.huge - math.huge
  v = unpack "<d", pack("<d", nan)
  assert v ~= v, "expected NaN, got: #{v}"

util.summary "pack_compat_float"
