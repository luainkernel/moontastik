util = require"ipparse.lib.util"
{:test} = util
udp = require"ipparse.l4.udp"
{:checksum6} = require "ipparse.l3.lib"

test "parse extracts spt, dpt, len, checksum", ->
  u = udp.new {spt: 12345, dpt: 53, checksum: 0}
  raw = tostring u
  parsed, _ = udp.parse raw, 1
  assert parsed.spt == 12345, "spt should be 12345, got #{parsed.spt}"
  assert parsed.dpt == 53, "dpt should be 53, got #{parsed.dpt}"
  assert parsed.len == 8, "len should be 8 (no data), got #{parsed.len}"
  assert parsed.checksum == 0, "checksum should be 0, got #{parsed.checksum}"

test "pack sets len=8 when no data", ->
  u = udp.new {spt: 1000, dpt: 2000, checksum: 0}
  raw = tostring u
  parsed, _ = udp.parse raw, 1
  assert parsed.len == 8, "len should be 8 with no data, got #{parsed.len}"

test "pack sets len=8+data_len when data present", ->
  u = udp.new {spt: 1000, dpt: 2000, checksum: 0, data: "hello"}
  raw = tostring u
  parsed, _ = udp.parse raw, 1
  assert parsed.len == 13, "len should be 13 (8+5), got #{parsed.len}"

test "round-trip: new -> tostring -> parse", ->
  u = udp.new {spt: 5678, dpt: 1234, checksum: 0xabcd}
  raw = tostring u
  parsed, _ = udp.parse raw, 1
  assert parsed.spt == 5678, "round-trip spt mismatch"
  assert parsed.dpt == 1234, "round-trip dpt mismatch"
  assert parsed.checksum == 0xabcd, "round-trip checksum mismatch"

test "data_off is off+8", ->
  u = udp.new {spt: 100, dpt: 200, checksum: 0}
  raw = tostring u
  parsed, _ = udp.parse raw, 1
  assert parsed.data_off == 9, "data_off should be 9 (1+8), got #{parsed.data_off}"

test "packed output is 8 bytes with no data", ->
  u = udp.new {spt: 100, dpt: 200, checksum: 0}
  raw = tostring u
  assert #raw == 8, "UDP header with no data should be 8 bytes, got #{#raw}"

test "packed output includes data", ->
  u = udp.new {spt: 100, dpt: 200, checksum: 0, data: "abc"}
  raw = tostring u
  assert #raw == 11, "UDP with 3-byte data should be 11 bytes, got #{#raw}"

test "checksum6 computes IPv6 UDP pseudo-header checksum", ->
  src = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  dst = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  pkt = tostring udp.new spt: 1234, dpt: 443, checksum: 0, data: "hello"
  got = udp.checksum6 src, dst, pkt
  expected = checksum6 src, dst, 17, pkt
  expected = 0xFFFF if expected == 0
  assert got == expected, "checksum6 mismatch: got #{got}, expected #{expected}"

util.summary "l4/udp"
