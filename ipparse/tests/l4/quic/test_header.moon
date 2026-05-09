-- tests/l4/quic/test_header.moon
-- Tests for QUIC long/short header parsing

util = require "ipparse.lib.util"
{:test} = util
pack: sp, unpack: su = require "ipparse.lib.pack_compat"
quic = require "ipparse.l4.quic"
v1   = require "ipparse.l4.quic.v1"

-- Helper: build a minimal QUIC v1 Initial long-header packet (no payload)
-- byte1: 0xC0 = HEADER_FORM(1) + FIXED_BIT(1) + PKT_TYPE(Initial=0x00) + TYPE_BITS(0)
-- version: 0x00000001
-- dcid: 8 bytes
-- scid: 0 bytes
-- token_length: 0 (VarInt 1-byte)
-- length: 4 (VarInt 1-byte, represents pn(1) + payload(3))
-- packet number: 0x00 (1 byte, unprotected for test)
dcid = "\x01\x02\x03\x04\x05\x06\x07\x08"
build_initial_pkt = ->
  sp(">B I4 s1 s1 B B B", 0xC0, 1, dcid, "", 0, 4, 0)

test "header: parse long header returns table", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert type(h) == "table", "expected table"

test "header: long_header flag is true", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.long_header == true

test "header: version parsed correctly", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.version == 1, "expected version 1, got #{h.version}"

test "header: dst_connection_id parsed correctly", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.dst_connection_id == dcid, "dcid mismatch"

test "header: src_connection_id empty", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.src_connection_id == "", "scid should be empty"

test "header: token is empty for zero token_length", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.token == "" or h.token == nil, "token should be empty"

test "header: pkt_type is 0x00 for Initial", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  -- pkt_type = byte1 & 0x30 = 0xC0 & 0x30 = 0x00
  assert h.pkt_type == 0x00, "expected pkt_type 0x00, got #{h.pkt_type}"

test "header: pn_off points past fixed fields", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  -- byte1(1) + version(4) + dcid_len(1)+dcid(8) + scid_len(1)+scid(0) + token_len(1) + length(1) = 17
  -- pn_off points to first byte after the length field, i.e. offset 18
  assert h.pn_off == 18, "expected pn_off=18, got #{h.pn_off}"

-- Short header: HEADER_FORM=0, FIXED_BIT=1
test "header: parse short header", ->
  pkt = "\x40" .. dcid  -- byte1=0x40 (short), then dst_connection_id
  h, _ = quic.parse pkt, 1, dcid
  assert h.long_header == nil or h.long_header == false, "expected short header"

test "header: parse advances offset correctly", ->
  pkt = build_initial_pkt!
  _, off = quic.parse pkt, 1
  -- pn_off = 18 (past length field), so returned offset should be 18
  assert off == 18, "expected off=18, got #{off}"

-- Byte1 flag access via v1 metatable
test "header: HEADER_FORM bit accessible via metatable", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  -- HEADER_FORM mask = 0x80, byte1 = 0xC0 → 0xC0 & 0x80 = 0x80
  assert h.HEADER_FORM == 0x80, "HEADER_FORM should be 0x80"

test "header: FIXED_BIT accessible", ->
  pkt = build_initial_pkt!
  h, _ = quic.parse pkt, 1
  assert h.FIXED_BIT == 0x40, "FIXED_BIT should be 0x40"

util.summary "header"
