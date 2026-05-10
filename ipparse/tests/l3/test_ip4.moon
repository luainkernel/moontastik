util = require"ipparse.lib.util"
{:test} = util
ip4 = require"ipparse.l3.ip4"
fragmented_ip4 = require"ipparse.l3.fragmented_ip4"

test "ip42s converts 4 bytes to dotted decimal", ->
  result = ip4.ip42s "\xc0\xa8\x01\x01"
  assert result == "192.168.1.1", "expected '192.168.1.1', got '#{result}'"

test "s2ip4 converts dotted decimal to 4 bytes", ->
  result = ip4.s2ip4 "192.168.1.1"
  assert result == "\xc0\xa8\x01\x01", "s2ip4 failed"

test "ip42s/s2ip4 round-trip", ->
  original = "\x0a\x00\x00\x01"
  assert ip4.s2ip4(ip4.ip42s(original)) == original, "ip42s/s2ip4 round-trip failed"

test "net42s converts 5 bytes to CIDR notation", ->
  -- mask=24, then 192.168.1.0
  bin = "\x18\xc0\xa8\x01\x00"
  result = ip4.net42s bin
  assert result == "192.168.1.0/24", "expected '192.168.1.0/24', got '#{result}'"

test "s2net4 converts CIDR to 5 bytes", ->
  result = ip4.s2net4 "192.168.1.0/24"
  assert result == "\x18\xc0\xa8\x01\x00", "s2net4 failed"

test "net42s/s2net4 round-trip", ->
  original = "10.0.0.0/8"
  assert ip4.net42s(ip4.s2net4(original)) == original, "net42s/s2net4 round-trip failed"

test "parse extracts version=4", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 17, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.version == 4, "version should be 4, got #{parsed.version}"

test "parse extracts protocol", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 17, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.protocol == 17, "protocol should be 17, got #{parsed.protocol}"

test "parse extracts src and dst", ->
  src = ip4.s2ip4 "192.168.1.1"
  dst = ip4.s2ip4 "192.168.1.2"
  hdr = ip4.new {:src, :dst, protocol: 6, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.src == src, "src mismatch"
  assert parsed.dst == dst, "dst mismatch"

test "new sets default ttl=64", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  assert hdr.ttl == 64, "default ttl should be 64, got #{hdr.ttl}"

test "new sets default version=4", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  assert hdr.version == 4, "default version should be 4, got #{hdr.version}"

test "pack calculates non-zero checksum", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.checksum ~= 0, "checksum should be non-zero for non-trivial header"

test "data_off is off+20 for IHL=5", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.data_off == 21, "data_off should be 21 (1+20), got #{parsed.data_off}"

test "DF flag readable via __index", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: "", DF: true}
  assert hdr.DF == true, "DF flag should be true"

test "DF flag false when not set", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  assert hdr.DF == false, "DF flag should be false when not set"

test "DF flag settable via __newindex", ->
  hdr = ip4.new {src: ip4.s2ip4"1.2.3.4", dst: ip4.s2ip4"5.6.7.8", protocol: 6, options: ""}
  hdr.DF = true
  assert hdr.DF == true, "DF flag should be true after setting"

test "parse round-trip preserves ihl=5", ->
  hdr = ip4.new {src: ip4.s2ip4"10.0.0.1", dst: ip4.s2ip4"10.0.0.2", protocol: 6, options: ""}
  raw = tostring hdr
  parsed, _ = ip4.parse raw, 1
  assert parsed.ihl == 5, "ihl should be 5, got #{parsed.ihl}"

test "collect handles fragmented packets correctly", ->
  -- Create a large payload (10KB) that requires fragmentation
  payload = data_new 10240
  payload\setstring 0, "a" * 10240

  -- Create a fragmented ID to track this packet
  id = "frag_test"

  -- Initialize fragmented state
  fragmented_ip4.fragmented[id] = {}

  -- Simulate multiple fragments
  fragments = {}
  total_len = 0

  -- Fragment 1: offset 0, 4KB
  frag1 = {
      id: id,
      skb: data_new 4096,
      off: 0,
      data_off: 0,
      data_len: 4096,
      mf: 1 -- More Fragments
  }
  frag1\setstring 0, "a" * 4096
  fragments[#fragments + 1] = frag1
  total_len += 4096

  -- Fragment 2: offset 4096, 4KB
  frag2 = {
      id: id,
      skb: data_new 4096,
      off: 4096,
      data_off: 4096,
      data_len: 4096,
      mf: 0 -- Last Fragment
  }
  frag2\setstring 0, "a" * 4096
  fragments[#fragments + 1] = frag2
  total_len += 4096

  -- Fragment 3: offset 8192, 2KB (last 2KB of payload)
  frag3 = {
      id: id,
      skb: data_new 2048,
      off: 8192,
      data_off: 8192,
      data_len: 2048,
      mf: 0
  }
  frag3\setstring 0, "a" * 2048
  fragments[#fragments + 1] = frag3
  total_len += 2048

  -- Process each fragment through collect
  for frag in *fragments
      ip = fragmented_ip4.collect(frag.skb, frag)

      -- Verify final IP object
      assert ip.__len == total_len, "Total length should be #{total_len}, got #{ip.__len}"
      assert ip.skb\getstring 0 == "a" * total_len, "Reconstructed payload should match original"
      assert ip.skb\len == total_len, "skb length should match total length"

  -- Verify fragmented state is cleared
  assert fragmented_ip4.fragmented[id] == nil, "fragmented state should be cleared after collection"

util.summary "l3/ip4"
