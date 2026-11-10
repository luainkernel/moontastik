--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
ip6 = require"ipparse.l3.ip6"
udp = require"ipparse.l4.udp"
{:checksum6} = require"ipparse.l3.lib"
unpack: su = require "ipparse.lib.pack_compat"

test "ip62s compresses zero runs per RFC 5952", ->
  bin = ip6.s2ip6 "0:0:0:0:0:0:0:1"
  result = ip6.ip62s bin
  assert result == "::1", "expected '::1', got '#{result}'"

test "s2ip6 converts address to 16 bytes", ->
  result = ip6.s2ip6 "0:0:0:0:0:0:0:1"
  expected = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001"
  assert result == expected, "s2ip6(0:0:0:0:0:0:0:1) mismatch"

test "s2ip6 full address", ->
  result = ip6.s2ip6 "2001:db8:0:0:0:0:0:1"
  assert #result == 16, "s2ip6 should return 16 bytes, got #{#result}"

test "ip62s/s2ip6 round-trip preserves bytes", ->
  original = "\032\001\013\184\000\000\000\000\000\000\000\000\000\000\000\001"
  s = ip6.ip62s original
  assert s == "2001:db8::1", "expected '2001:db8::1', got '#{s}'"
  converted = ip6.s2ip6 s
  assert converted == original, "ip62s/s2ip6 round-trip failed"

test "parse extracts version=6", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  raw = tostring hdr
  parsed, _ = ip6.parse raw, 1
  assert parsed.version == 6, "version should be 6, got #{parsed.version}"

test "parse extracts next_header", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  raw = tostring hdr
  parsed, _ = ip6.parse raw, 1
  assert parsed.next_header == 17, "next_header should be 17, got #{parsed.next_header}"

test "parse extracts hop_limit", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 6
    hop_limit: 128
  }
  raw = tostring hdr
  parsed, _ = ip6.parse raw, 1
  assert parsed.hop_limit == 128, "hop_limit should be 128, got #{parsed.hop_limit}"

test "new sets default hop_limit=64", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 6
  }
  assert hdr.hop_limit == 64, "default hop_limit should be 64, got #{hdr.hop_limit}"

test "new sets default version=6", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 6
  }
  assert hdr.version == 6, "version should be 6, got #{hdr.version}"

test "round-trip preserves src and dst", ->
  src = ip6.s2ip6 "::1"
  dst = ip6.s2ip6 "::2"
  hdr = ip6.new {:src, :dst, next_header: 17}
  raw = tostring hdr
  parsed, _ = ip6.parse raw, 1
  assert parsed.src == src, "src mismatch after round-trip"
  assert parsed.dst == dst, "dst mismatch after round-trip"

test "s2net6 defaults to /128 when no mask given", ->
  result = ip6.s2net6 "::1"
  assert #result == 17, "s2net6 should return 17 bytes, got #{#result}"
  mask = result\byte 1
  assert mask == 128, "default mask should be 128, got #{mask}"

test "pack recomputes vtf from traffic_class", ->
  p = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  p.traffic_class = 0xff
  raw = tostring p
  second = raw\byte 2
  assert second == 0xf0, "second octet should be 0xf0, got #{second}"

test "re-packed parsed IPv6 header is byte-identical", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "2001:db8::1"
    dst: ip6.s2ip6 "2001:db8::2"
    next_header: 17
    traffic_class: 0xab
    flow_label: 0x12345
  }
  raw1 = tostring hdr
  parsed, _ = ip6.parse raw1, 1
  raw2 = tostring parsed
  assert raw2 == raw1, "re-packed parsed header should be identical"

test "UDP/IPv6 pack emits 0xFFFF for a zero checksum", ->
  src = ip6.s2ip6 "2001:db8::1"
  dst = ip6.s2ip6 "2001:db8::2"
  segment = udp.new {spt: 1234, dpt: 53, checksum: 0, data: "\159\094"}
  hdr = ip6.new {src: src, dst: dst, next_header: 17, data: segment}
  raw = tostring hdr
  csum = su ">H", raw, 47
  assert csum == 0xffff, "zero UDP checksum should be emitted as 0xFFFF, got #{csum}"
  verify = checksum6 src, dst, 17, raw\sub 41
  assert verify == 0, "UDP checksum should verify, got #{verify}"

test "data_off is off+40 for IPv6 header", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  raw = tostring hdr
  parsed, next_off = ip6.parse raw, 1
  assert parsed.data_off == 41, "data_off should be 41 (1+40), got #{parsed.data_off}"
util.summary "l3/ip6"
