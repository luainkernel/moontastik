--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_bit_compat.moon
-- Tests for the bitwise compatibility layer, notably variadic band/bor/bxor

util = require "ipparse.lib.util"
{:test} = util
{ :band, :bor, :bxor, :arshift } = require "ipparse.lib.bit_compat"
-- Test the pure-Lua fallback directly wherever it can run, so it is exercised
-- even when the host has LuaJIT's `bit` or Lua 5.2+'s `bit32`.
-- It is only the last-resort fallback of `bit_compat` (Lua 5.1 without `bit`)
-- and relies on `math.floor`, which the Lua 5.5 kernel runtime lacks: the
-- `bit_pure` cases below therefore only run where `math.floor` exists.
pure = require "ipparse.lib.bit_pure"

test_pure = (name, fn) ->
  test name, fn if math.floor

test "bit_compat: bor with 1 argument", ->
  assert bor(5) == 5, "bor(5) != 5"

test "bit_compat: bor with 2 arguments", ->
  assert bor(1, 2) == 3, "bor(1,2) != 3"

test "bit_compat: bor with 7 arguments", ->
  assert bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127"

test "bit_compat: bor with 7 TCP flag arguments", ->
  assert bor(0, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01) == 63, "TCP flags != 63"

test "bit_compat: band with 3 arguments", ->
  assert band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28"

test "bit_compat: bxor with 3 arguments", ->
  assert bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51"

test "bit_compat: arshift sign-extends", ->
  assert arshift(-8, 1) == -4, "arshift(-8,1) != -4"
  assert arshift(8, 1) == 4, "arshift(8,1) != 4"

-- Expected values below are hardcoded from LuaJIT's `bit` library, which
-- returns SIGNED 32-bit results (e.g. bit.bor(0x80000000, 0) == -2147483648).
-- ipparse relies on that signedness in the QUIC VarInt encoder, which avoids
-- the negative int32 produced by `bor(0x80000000, value)`.

test_pure "bit_pure: band with 1 argument", ->
  assert pure.band(0xFF) == 255, "band(0xFF) != 255"

test_pure "bit_pure: band with 2 arguments", ->
  assert pure.band(-1, 0xFF) == 255, "band(-1,0xFF) != 255"
  assert pure.band(0xFFFFFFFF, 0xFFFF) == 65535, "band(0xFFFFFFFF,0xFFFF) != 65535"
  assert pure.band(0x80000000, 0x80000000) == -2147483648, "band of bit 31 != -2147483648"

test_pure "bit_pure: band with 3 arguments", ->
  assert pure.band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28"

test_pure "bit_pure: bor with 1 argument", ->
  assert pure.bor(5) == 5, "bor(5) != 5"
  assert pure.bor(0x80000000) == -2147483648, "bor(0x80000000) != -2147483648"

test_pure "bit_pure: bor with 2 arguments", ->
  assert pure.bor(1, 2) == 3, "bor(1,2) != 3"
  assert pure.bor(0x80000000, 0) == -2147483648, "bor(0x80000000,0) != -2147483648"
  assert pure.bor(0x80000000, 0xFF) == -2147483393, "bor(0x80000000,0xFF) != -2147483393"

test_pure "bit_pure: bor with 3 arguments", ->
  assert pure.bor(1, 2, 4) == 7, "bor(1,2,4) != 7"

test_pure "bit_pure: bor with 7 arguments", ->
  assert pure.bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127"

test_pure "bit_pure: bxor with 1 argument", ->
  assert pure.bxor(5) == 5, "bxor(5) != 5"

test_pure "bit_pure: bxor with 2 arguments", ->
  assert pure.bxor(0x80000000, 0xFFFFFFFF) == 2147483647, "bxor(0x80000000,0xFFFFFFFF) != 2147483647"
  assert pure.bxor(0x80000000, 0x80000000) == 0, "bxor(0x80000000,0x80000000) != 0"
  assert pure.bxor(-1, 0xFF) == -256, "bxor(-1,0xFF) != -256"

test_pure "bit_pure: bxor with 3 arguments", ->
  assert pure.bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51"

test_pure "bit_pure: bnot", ->
  assert pure.bnot(0) == -1, "bnot(0) != -1"
  assert pure.bnot(0xFFFFFFFF) == 0, "bnot(0xFFFFFFFF) != 0"
  assert pure.bnot(-1) == 0, "bnot(-1) != 0"

test_pure "bit_pure: lshift by 0, 1 and 31 bits", ->
  assert pure.lshift(3, 0) == 3, "lshift(3,0) != 3"
  assert pure.lshift(1, 1) == 2, "lshift(1,1) != 2"
  assert pure.lshift(1, 31) == -2147483648, "lshift(1,31) != -2147483648"

test_pure "bit_pure: lshift masks the shift count to 5 bits", ->
  assert pure.lshift(1, 32) == 1, "lshift(1,32) != 1"
  assert pure.lshift(1, 33) == 2, "lshift(1,33) != 2"

test_pure "bit_pure: rshift by 0, 1 and 31 bits", ->
  assert pure.rshift(3, 0) == 3, "rshift(3,0) != 3"
  assert pure.rshift(0x80000000, 1) == 1073741824, "rshift(0x80000000,1) != 1073741824"
  assert pure.rshift(0x80000000, 31) == 1, "rshift(0x80000000,31) != 1"
  assert pure.rshift(-1, 1) == 2147483647, "rshift(-1,1) != 2147483647"
  assert pure.rshift(0x80000000, 32) == -2147483648, "rshift(0x80000000,32) != -2147483648"

test_pure "bit_pure: arshift sign-extends", ->
  assert pure.arshift(3, 0) == 3, "arshift(3,0) != 3"
  assert pure.arshift(0x80000000, 1) == -1073741824, "arshift(0x80000000,1) != -1073741824"
  assert pure.arshift(-1, 1) == -1, "arshift(-1,1) != -1"
  assert pure.arshift(0x40000000, 1) == 536870912, "arshift(0x40000000,1) != 536870912"

test_pure "bit_pure: IPv6 version/traffic class/flow label round-trip", ->
  vtf = pure.bor(pure.lshift(6, 28), pure.lshift(0x12, 20), 0x34567)
  assert vtf == 1629701479, "vtf != 1629701479"
  assert pure.rshift(vtf, 28) == 6, "version != 6"
  assert pure.band(pure.rshift(vtf, 20), 0xFF) == 18, "traffic class != 18"
  assert pure.band(vtf, 0xFFFFF) == 214375, "flow label != 214375"

util.summary "bit_compat"
