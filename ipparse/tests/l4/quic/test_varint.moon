-- tests/l4/quic/test_varint.moon
-- Tests for QUIC VarInt encoding/decoding

util = require "ipparse.lib.util"
{:test} = util
{:parse_varint, :encode_varint} = require "ipparse.l4.quic.frames"

-- parse_varint: 1-byte (00xxxxxx)
test "varint: parse 1-byte value 0", ->
  v, off = parse_varint "\x00", 1
  assert v == 0 and off == 2, "expected 0, got #{v}"

test "varint: parse 1-byte value 63", ->
  v, off = parse_varint "\x3F", 1
  assert v == 63 and off == 2, "expected 63, got #{v}"

-- parse_varint: 2-byte (01xxxxxx)
test "varint: parse 2-byte value 64", ->
  v, off = parse_varint "\x40\x40", 1
  assert v == 64 and off == 3, "expected 64, got #{v}"

test "varint: parse 2-byte value 16383", ->
  v, off = parse_varint "\x7F\xFF", 1
  assert v == 16383 and off == 3, "expected 16383, got #{v}"

-- parse_varint: 4-byte (10xxxxxx)
test "varint: parse 4-byte value 16384", ->
  v, off = parse_varint "\x80\x00\x40\x00", 1
  assert v == 16384 and off == 5, "expected 16384, got #{v}"

-- encode_varint
test "varint: encode 0", ->
  assert encode_varint(0) == "\x00"

test "varint: encode 63", ->
  assert encode_varint(63) == "\x3F"

test "varint: encode 64", ->
  assert encode_varint(64) == "\x40\x40"

test "varint: encode 16383", ->
  assert encode_varint(16383) == "\x7F\xFF"

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
  v, _ = parse_varint encoded, 1
  assert v == value, "round-trip 8-byte value failed: got #{v}"

test "varint: truncated 8-byte returns nil", ->
  v, off = parse_varint "\xC0\x00", 1
  assert v == nil and off == 1, "expected nil with unchanged offset"

-- offset arithmetic
test "varint: parse at non-1 offset", ->
  data = "\xFF" .. "\x3F"  -- junk byte, then value 63
  v, off = parse_varint data, 2
  assert v == 63 and off == 3

util.summary "varint"
