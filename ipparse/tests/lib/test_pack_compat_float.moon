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

from_hex = (h) ->
  out = h\gsub "..", (cc) -> string.char tonumber cc, 16
  out

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

-- Big-endian 32-bit float, and its round-trip (also exercises the BE
-- float decoder branch).
test "pack_compat_float: >f bytes and unpack", ->
  got = pack ">f", -2.25
  expected = from_hex "c0100000"
  assert got == expected, "got: #{got}\nexp: #{expected}"
  v, pos = unpack ">f", got
  assert v == -2.25 and pos == 5, "got: #{v}, pos: #{pos}"

-- n is an alias for d (both 64-bit doubles).
test "pack_compat_float: n matches d", ->
  for prefix in *{">", "<"}
    for v in *{1.5, -2.5, 0.0}
      assert pack(prefix .. "n", v) == pack(prefix .. "d", v),
        "#{prefix}n differs from #{prefix}d for #{v}"
      r, pos = unpack prefix .. "n", pack(prefix .. "n", v)
      assert r == v and pos == 9, "#{prefix}n round-trip: #{r}, #{pos}"

test "pack_compat_float: d/f in the middle of a format", ->
  got = pack ">H d B", 1, 1.5, 2
  expected = from_hex("0001") .. from_hex("3ff8000000000000") .. from_hex("02")
  assert got == expected, "got: #{got}\nexp: #{expected}"
  a, b, c, pos = unpack ">H d B", got
  assert a == 1 and b == 1.5 and c == 2 and pos == 12,
    "got: #{a}, #{b}, #{c}, pos: #{pos}"

-- Truncated floating-point input must raise, as native string.unpack does.
test "pack_compat_float: unpack short f/d/n raises", ->
  cases = {
    {"f", from_hex "0000"}
    {"d", from_hex "00000000000000"}
    {"n", from_hex "00000000000000"}
    {">f", from_hex "c01000"}
  }
  for item in *cases
    fmt, s = item[1], item[2]
    ok, err = pcall unpack, fmt, s, 1
    assert not ok, "unpack('#{fmt}') on short data should raise"
    assert (tostring(err)\match "too short"),
      "unpack('#{fmt}'): expected 'data string too short', got: #{tostring err}"

-- packsize covers the float widths too.
test "pack_compat_float: packsize f/d/n", ->
  packsize = pack_compat.packsize or string.packsize
  assert packsize("f") == 4, "f"
  assert packsize("d") == 8, "d"
  assert packsize("n") == 8, "n"
  assert packsize(">H f d") == 14, ">H f d"
  assert packsize(">H d B") == 11, ">H d B"

util.summary "pack_compat_float"
