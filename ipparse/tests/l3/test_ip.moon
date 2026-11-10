--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
ip = require"ipparse.l3.ip"
ip4 = require"ipparse.l3.ip4"
ip6 = require"ipparse.l3.ip6"

test "ip2s for IPv4 returns dotted decimal", ->
  bin = ip4.s2ip4 "1.2.3.4"
  result = ip.ip2s bin
  assert result == "1.2.3.4", "expected '1.2.3.4', got '#{result}'"

test "ip2s for IPv6 returns colon-hex", ->
  bin = ip6.s2ip6 "::1"
  result = ip.ip2s bin
  assert type(result) == "string" and #result > 0, "ip2s for IPv6 should return non-empty string"

test "s2ip for IPv4 parses dotted decimal", ->
  result = ip.s2ip "192.168.0.1"
  assert result == ip4.s2ip4("192.168.0.1"), "s2ip IPv4 mismatch"
  assert #result == 4, "IPv4 should be 4 bytes"

test "s2ip for IPv6 parses colon-hex", ->
  result = ip.s2ip "::1"
  assert #result == 16, "IPv6 should be 16 bytes, got #{#result}"

test "parse dispatches to IPv4 for version 4 data", ->
  hdr = ip4.new {
    src: ip4.s2ip4 "1.2.3.4"
    dst: ip4.s2ip4 "5.6.7.8"
    protocol: 6
    options: ""
  }
  raw = tostring hdr
  parsed, _ = ip.parse raw, 1
  assert parsed ~= nil, "parse should not return nil"
  assert parsed.version == 4, "version should be 4, got #{parsed.version}"

test "parse dispatches to IPv6 for version 6 data", ->
  hdr = ip6.new {
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  raw = tostring hdr
  parsed, _ = ip.parse raw, 1
  assert parsed ~= nil, "parse should not return nil"
  assert parsed.version == 6, "version should be 6, got #{parsed.version}"

test "contains_ip: 192.168.1.5 in 192.168.1.0/24 is true", ->
  net = ip.s2net "192.168.1.0/24"
  addr = ip.s2ip "192.168.1.5"
  assert ip.contains_ip(net, addr) == true, "192.168.1.5 should be in 192.168.1.0/24"

test "contains_ip: 192.168.2.5 not in 192.168.1.0/24 is false", ->
  net = ip.s2net "192.168.1.0/24"
  addr = ip.s2ip "192.168.2.5"
  assert ip.contains_ip(net, addr) == false, "192.168.2.5 should NOT be in 192.168.1.0/24"

test "contains_ip: 10.0.0.1 in 10.0.0.0/8 is true", ->
  net = ip.s2net "10.0.0.0/8"
  addr = ip.s2ip "10.255.255.254"
  assert ip.contains_ip(net, addr) == true, "10.255.255.254 should be in 10.0.0.0/8"

test "contains_subnet: 192.168.1.128/25 in 192.168.1.0/24 is true", ->
  net = ip.s2net "192.168.1.0/24"
  subnet = ip.s2net "192.168.1.128/25"
  assert ip.contains_subnet(net, subnet) == true, "192.168.1.128/25 should be in 192.168.1.0/24"

test "contains_subnet: 192.168.2.0/24 not in 192.168.1.0/24 is false", ->
  net = ip.s2net "192.168.1.0/24"
  subnet = ip.s2net "192.168.2.0/24"
  assert ip.contains_subnet(net, subnet) == false, "192.168.2.0/24 should NOT be in 192.168.1.0/24"

test "s2net/net2s round-trip for IPv4", ->
  original = "10.0.0.0/8"
  assert ip.net2s(ip.s2net(original)) == original, "net2s/s2net round-trip failed"

test "ip.pack packs an IPv6 header as 40 bytes", ->
  hdr = ip.new {
    version: 6
    src: ip6.s2ip6 "::1"
    dst: ip6.s2ip6 "::2"
    next_header: 17
  }
  raw = ip.pack hdr
  assert #raw == 40, "packed IPv6 header should be 40 bytes, got #{#raw}"
  parsed, _ = ip.parse raw, 1
  assert parsed ~= nil, "packed IPv6 header should parse back"
  assert parsed.version == 6, "version should be 6, got #{parsed.version}"
test "contains_ip: /0 contains every IPv4 address", ->
  net = ip.s2net "0.0.0.0/0"
  assert ip.contains_ip(net, ip.s2ip("1.2.3.4")) == true, "1.2.3.4 should be in 0.0.0.0/0"
  assert ip.contains_ip(net, ip.s2ip("255.255.255.255")) == true, "255.255.255.255 should be in 0.0.0.0/0"

test "contains_ip: /8 included and excluded", ->
  net = ip.s2net "10.0.0.0/8"
  assert ip.contains_ip(net, ip.s2ip("10.1.2.3")) == true, "10.1.2.3 should be in 10.0.0.0/8"
  assert ip.contains_ip(net, ip.s2ip("11.1.2.3")) == false, "11.1.2.3 should NOT be in 10.0.0.0/8"

test "contains_ip: /13 included and excluded", ->
  net = ip.s2net "192.168.0.0/13"
  assert ip.contains_ip(net, ip.s2ip("192.175.255.255")) == true, "192.175.255.255 should be in 192.168.0.0/13"
  assert ip.contains_ip(net, ip.s2ip("192.184.0.1")) == false, "192.184.0.1 should NOT be in 192.168.0.0/13"

test "contains_ip: /32 included and excluded", ->
  net = ip.s2net "1.2.3.4/32"
  assert ip.contains_ip(net, ip.s2ip("1.2.3.4")) == true, "1.2.3.4 should be in 1.2.3.4/32"
  assert ip.contains_ip(net, ip.s2ip("1.2.3.5")) == false, "1.2.3.5 should NOT be in 1.2.3.4/32"

test "contains_ip: /64 included and excluded (IPv6)", ->
  net = ip.s2net "2001:db8::/64"
  assert ip.contains_ip(net, ip.s2ip("2001:db8::1")) == true, "2001:db8::1 should be in 2001:db8::/64"
  assert ip.contains_ip(net, ip.s2ip("2001:db9::1")) == false, "2001:db9::1 should NOT be in 2001:db8::/64"

test "contains_ip: /65 included and excluded (IPv6)", ->
  net = ip.s2net "2001:db8::/65"
  assert ip.contains_ip(net, ip.s2ip("2001:db8:0:0:4000::")) == true, "4000:: should be in 2001:db8::/65"
  assert ip.contains_ip(net, ip.s2ip("2001:db8:0:0:8000::")) == false, "8000:: should NOT be in 2001:db8::/65"

test "contains_ip: /128 included and excluded (IPv6)", ->
  net = ip.s2net "2001:db8::/128"
  assert ip.contains_ip(net, ip.s2ip("2001:db8::")) == true, "2001:db8:: should be in 2001:db8::/128"
  assert ip.contains_ip(net, ip.s2ip("2001:db8::1")) == false, "2001:db8::1 should NOT be in 2001:db8::/128"

test "contains_ip: explicit nmask is honoured", ->
  net = ip.s2net "192.168.1.0/24"
  assert ip.contains_ip(net, ip.s2ip("192.168.1.5"), 24) == true, "explicit /24 should contain 192.168.1.5"
  assert ip.contains_ip(net, ip.s2ip("192.168.2.5"), 24) == false, "explicit /24 should NOT contain 192.168.2.5"
  net6 = ip.s2net "2001:db8::/64"
  assert ip.contains_ip(net6, ip.s2ip("2001:db8::1"), 64) == true, "explicit /64 should contain 2001:db8::1"
  assert ip.contains_ip(net6, ip.s2ip("2001:db9::1"), 64) == false, "explicit /64 should NOT contain 2001:db9::1"

util.summary "l3/ip"
