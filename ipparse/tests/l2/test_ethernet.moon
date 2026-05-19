--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
eth = require"ipparse.l2.ethernet"
sp = require("ipparse.lib.pack_compat").pack

-- Build a 14-byte Ethernet header: dst=aa:bb:cc:dd:ee:ff, src=00:11:22:33:44:55, proto=0x0800
eth_raw = sp("c6c6>H", "\xaa\xbb\xcc\xdd\xee\xff", "\x00\x11\x22\x33\x44\x55", 0x0800)

test "mac2s converts binary to string", ->
  result = eth.mac2s "\xaa\xbb\xcc\xdd\xee\xff"
  assert result == "aa:bb:cc:dd:ee:ff", "expected 'aa:bb:cc:dd:ee:ff', got '#{result}'"

test "s2mac converts string to binary", ->
  result = eth.s2mac "aa:bb:cc:dd:ee:ff"
  assert result == "\xaa\xbb\xcc\xdd\xee\xff", "s2mac failed"

test "mac2s/s2mac round-trip", ->
  original = "\x12\x34\x56\x78\x9a\xbc"
  assert eth.s2mac(eth.mac2s(original)) == original, "mac2s/s2mac round-trip failed"

test "parse extracts dst MAC", ->
  frame, next_off = eth.parse eth_raw, 1
  assert frame.dst == "\xaa\xbb\xcc\xdd\xee\xff", "dst MAC mismatch"

test "parse extracts src MAC", ->
  frame, next_off = eth.parse eth_raw, 1
  assert frame.src == "\x00\x11\x22\x33\x44\x55", "src MAC mismatch"

test "parse extracts protocol", ->
  frame, next_off = eth.parse eth_raw, 1
  assert frame.protocol == 0x0800, "protocol should be 0x0800, got #{frame.protocol}"

test "parse returns correct next offset", ->
  frame, next_off = eth.parse eth_raw, 1
  assert next_off == 15, "next_off should be 15 (after 14-byte header), got #{next_off}"

test "parse data_off is 15", ->
  frame, next_off = eth.parse eth_raw, 1
  assert frame.data_off == 15, "data_off should be 15, got #{frame.data_off}"

test "proto IP4 == 0x0800", ->
  assert eth.proto.IP4 == 0x0800, "IP4 proto should be 0x0800, got #{eth.proto.IP4}"

test "proto reverse lookup 0x0800 == IP4", ->
  assert eth.proto[0x0800] == "IP4", "reverse lookup 0x0800 should be 'IP4', got '#{eth.proto[0x0800]}'"

test "proto IP6 == 0x86DD", ->
  assert eth.proto.IP6 == 0x86DD, "IP6 proto should be 0x86DD"

test "new + tostring round-trip", ->
  frame = eth.new {
    dst: "\xaa\xbb\xcc\xdd\xee\xff"
    src: "\x00\x11\x22\x33\x44\x55"
    protocol: 0x0800
  }
  raw = tostring frame
  parsed, _ = eth.parse raw, 1
  assert parsed.dst == "\xaa\xbb\xcc\xdd\xee\xff", "round-trip dst mismatch"
  assert parsed.src == "\x00\x11\x22\x33\x44\x55", "round-trip src mismatch"
  assert parsed.protocol == 0x0800, "round-trip protocol mismatch"

-- Build an 18-byte 802.1Q-tagged frame: same MACs, VLAN 6, inner proto=0x0800
eth_vlan_raw = sp("c6c6>HHH", "\xaa\xbb\xcc\xdd\xee\xff", "\x00\x11\x22\x33\x44\x55", 0x8100, 6, 0x0800)

test "parse detects 802.1Q tag and extracts vlan", ->
  frame, next_off = eth.parse eth_vlan_raw, 1
  assert frame.vlan == 6, "vlan should be 6, got #{frame.vlan}"

test "parse 802.1Q: inner protocol is correct", ->
  frame, _ = eth.parse eth_vlan_raw, 1
  assert frame.protocol == 0x0800, "inner protocol should be 0x0800, got #{frame.protocol}"

test "parse 802.1Q: data_off is 19 (18-byte header + 1-based)", ->
  frame, next_off = eth.parse eth_vlan_raw, 1
  assert frame.data_off == 19, "data_off should be 19, got #{frame.data_off}"
  assert next_off == 19, "next_off should be 19, got #{next_off}"

test "parse untagged frame: vlan is nil", ->
  frame, _ = eth.parse eth_raw, 1
  assert frame.vlan == nil, "vlan should be nil for untagged frame, got #{frame.vlan}"

test "new with vlan: tostring produces 802.1Q frame", ->
  frame = eth.new {
    dst: "\xaa\xbb\xcc\xdd\xee\xff"
    src: "\x00\x11\x22\x33\x44\x55"
    protocol: 0x0800
    vlan: 6
  }
  assert tostring(frame) == eth_vlan_raw, "VLAN-tagged frame bytes mismatch"

test "new with vlan=0: tostring produces plain frame (no tag)", ->
  frame = eth.new {
    dst: "\xaa\xbb\xcc\xdd\xee\xff"
    src: "\x00\x11\x22\x33\x44\x55"
    protocol: 0x0800
    vlan: 0
  }
  assert tostring(frame) == eth_raw, "vlan=0 should produce plain frame"

test "new + tostring round-trip with vlan", ->
  frame = eth.new {
    dst: "\xaa\xbb\xcc\xdd\xee\xff"
    src: "\x00\x11\x22\x33\x44\x55"
    protocol: 0x0800
    vlan: 42
  }
  parsed, _ = eth.parse tostring(frame), 1
  assert parsed.vlan == 42, "round-trip vlan mismatch: got #{parsed.vlan}"
  assert parsed.protocol == 0x0800, "round-trip protocol mismatch"
  assert parsed.dst == "\xaa\xbb\xcc\xdd\xee\xff", "round-trip dst mismatch"

util.summary "l2/ethernet"
