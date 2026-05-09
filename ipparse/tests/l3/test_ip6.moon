util = require"ipparse.lib.util"
{:test} = util
ip6 = require"ipparse.l3.ip6"

test "ip62s converts 16 bytes to colon-hex", ->
  -- Use fully expanded address to avoid s2ip6 compression-parsing quirks
  bin = ip6.s2ip6 "0:0:0:0:0:0:0:1"
  result = ip6.ip62s bin
  assert result == "0:0:0:0:0:0:0:1", "expected '0:0:0:0:0:0:0:1', got '#{result}'"

test "s2ip6 converts address to 16 bytes", ->
  result = ip6.s2ip6 "0:0:0:0:0:0:0:1"
  expected = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  assert result == expected, "s2ip6(0:0:0:0:0:0:0:1) mismatch"

test "s2ip6 full address", ->
  result = ip6.s2ip6 "2001:db8:0:0:0:0:0:1"
  assert #result == 16, "s2ip6 should return 16 bytes, got #{#result}"

test "ip62s/s2ip6 round-trip preserves bytes", ->
  original = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  converted = ip6.s2ip6(ip6.ip62s(original))
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
