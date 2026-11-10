--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_varint.moon
-- Tests for QUIC VarInt encoding/decoding

util = require "ipparse.lib.util"
{:test} = util
{:parse_varint, :encode_varint} = require "ipparse.l4.quic.frames"

-- parse_varint: 1-byte (00xxxxxx)
test "varint: parse 1-byte value 0", ->
  v, off = parse_varint "\000", 1
  assert v == 0 and off == 2, "expected 0, got #{v}"

test "varint: parse 1-byte value 63", ->
  v, off = parse_varint "\063", 1
  assert v == 63 and off == 2, "expected 63, got #{v}"

-- parse_varint: 2-byte (01xxxxxx)
test "varint: parse 2-byte value 64", ->
  v, off = parse_varint "\064\064", 1
  assert v == 64 and off == 3, "expected 64, got #{v}"

test "varint: parse 2-byte value 16383", ->
  v, off = parse_varint "\127\255", 1
  assert v == 16383 and off == 3, "expected 16383, got #{v}"

-- parse_varint: 4-byte (10xxxxxx)
test "varint: parse 4-byte value 16384", ->
  v, off = parse_varint "\128\000\064\000", 1
  assert v == 16384 and off == 5, "expected 16384, got #{v}"

-- encode_varint
test "varint: encode 0", ->
  assert encode_varint(0) == "\000"

test "varint: encode 63", ->
  assert encode_varint(63) == "\063"

test "varint: encode 64", ->
  assert encode_varint(64) == "\064\064"

test "varint: encode 16383", ->
  assert encode_varint(16383) == "\127\255"

-- round-trip
test "varint: round-trip 500", ->
  encoded = encode_varint 500
  v, _ = parse_varint encoded, 1
  assert v == 500, "round-trip 500 failed: got #{v}"

test "varint: round-trip 70000", ->
  encoded = encode_varint 70000
  v, _ = parse_varint encoded, 1
  assert v == 70000, "round-trip 70000 failed: got #{v}"

test "varint: round-trip 8-byte value", ->
  value = 4886718345 -- 0x123456789
  encoded = encode_varint value
  assert encoded == "\192\000\000\001\035\069\103\137", "8-byte encoding mismatch"
  v, _ = parse_varint encoded, 1
  assert v == value, "round-trip 8-byte value failed: got #{v}"

-- 2^62-1 is not exactly representable as a double (LuaJIT): only run where
-- native integers exist. Same condition as frames.moon's native_int: in the
-- kernel math.type is absent but native 64-bit integers do exist.
if math.floor == nil or math.type ~= nil
  test "varint: round-trip 8-byte max value", ->
    value = 4611686018427387903 -- 0x3FFFFFFFFFFFFFFF (2^62-1)
    encoded = encode_varint value
    assert encoded == "\255\255\255\255\255\255\255\255", "max 8-byte encoding mismatch"
    v, _ = parse_varint encoded, 1
    assert v == value, "round-trip max 8-byte value failed: got #{v}"

test "varint: truncated 8-byte returns nil", ->
  v, off = parse_varint "\192\000", 1
  assert v == nil and off == 1, "expected nil with unchanged offset"

-- offset arithmetic
test "varint: parse at non-1 offset", ->
  data = "\255" .. "\063"  -- junk byte, then value 63
  v, off = parse_varint data, 2
  assert v == 63 and off == 3

util.summary "varint"
