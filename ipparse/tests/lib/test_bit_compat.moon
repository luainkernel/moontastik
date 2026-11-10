--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_bit_compat.moon
-- Tests for the bitwise compatibility layer, notably variadic band/bor/bxor

util = require "ipparse.lib.util"
{:test} = util
{ :band, :bor, :bxor } = require "ipparse.lib.bit_compat"

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

util.summary "bit_compat"
