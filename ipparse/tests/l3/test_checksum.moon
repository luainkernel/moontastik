--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
pack: sp = require "ipparse.lib.pack_compat"
{:checksum, :checksum6} = require"ipparse.l3.lib"
ip4 = require"ipparse.l3.ip4"

test "checksum of 0xffff is 0", ->
  result = checksum "\xff\xff"
  assert result == 0, "checksum(0xffff) should be 0, got #{result}"

test "checksum of 0x0000 is 0xffff", ->
  result = checksum "\x00\x00"
  assert result == 0xffff, "checksum(0x0000) should be 0xffff, got #{result}"

test "checksum of packed header is 0", ->
  -- Build a valid IPv4 header using new+pack, then verify its checksum
  hdr = ip4.new {
    src: ip4.s2ip4 "192.168.1.1"
    dst: ip4.s2ip4 "192.168.1.2"
    protocol: 6
    options: ""
  }
  raw = tostring hdr
  -- The header is 20 bytes; checksum of those 20 bytes should be 0
  header_bytes = raw\sub 1, 20
  result = checksum header_bytes
  assert result == 0, "checksum of valid IP header should be 0, got #{result}"

test "checksum odd-length pads with zero", ->
  -- Odd-length input should be padded; "\xff" = "\xff\x00" padded → checksum = 0xff00 → bnot = 0x00ff
  result = checksum "\xff"
  assert result == 0x00ff, "checksum(\\xff) should be 0x00ff, got #{result}"

test "checksum6 matches IPv6 pseudo-header formula", ->
  src = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  dst = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  payload = "abcdef"
  got = checksum6 src, dst, 17, payload
  expected = checksum sp(">c16c16 I4 xxx B c#{#payload}", src, dst, #payload, 17, payload)
  assert got == expected, "checksum6 mismatch: got #{got}, expected #{expected}"
util.summary "l3/checksum"
