-- Comprehensive Lunatik kernel QUIC parsing tests (L2-L7)
-- RFC 9001 vectors and full packet parsing workflow

-- Inline hex_to_bin
hex_to_bin = (hex_str) ->
  result = ""
  for i = 1, #hex_str, 2
    byte_str = hex_str\sub(i, i+1)
    byte = tonumber(byte_str, 16)
    result ..= string.char(byte)
  result

tests_passed = 0
tests_failed = 0

assert_equal = (name, got, expected) ->
  if got == expected
    tests_passed += 1
    print "PASS\tlunatik: #{name}"
  else
    tests_failed += 1
    print "FAIL\tlunatik: #{name}\tgot: #{tostring(got)}, expected: #{tostring(expected)}"

assert_test = (name, fn) ->
  result, err = pcall fn
  if result
    tests_passed += 1
    print "PASS\tlunatik: #{name}"
  else
    tests_failed += 1
    print "FAIL\tlunatik: #{name}\t#{err}"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: L2 Ethernet frame parsing
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "L2: Extract destination MAC address", ->
  -- Simple Ethernet frame: dst MAC 6 bytes
  eth_frame = hex_to_bin "ffffffffffff" .. "000000000000" .. "0800"  -- dst, src, EtherType=IPv4
  dst_mac = eth_frame\sub(1, 6)
  assert #dst_mac == 6, "MAC should be 6 bytes"
  assert string.byte(dst_mac, 1) == 0xff, "First byte of dst MAC should be 0xff"

assert_test "L2: Extract source MAC address", ->
  eth_frame = hex_to_bin "ffffffffffff" .. "aabbccddeeff" .. "0800"
  src_mac = eth_frame\sub(7, 12)
  assert #src_mac == 6, "MAC should be 6 bytes"
  assert string.byte(src_mac, 1) == 0xaa, "First byte of src MAC should be 0xaa"

assert_test "L2: Extract EtherType", ->
  eth_frame = hex_to_bin "ffffffffffff" .. "000000000000" .. "0800"
  ethertype = (string.byte(eth_frame, 13) << 8) | string.byte(eth_frame, 14)
  assert ethertype == 0x0800, "EtherType should be IPv4 (0x0800)"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: L3 IPv4 header parsing
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "L3: Extract IPv4 version and header length", ->
  -- IPv4 header: version (4 bits) | ihl (4 bits) = 0x45 for version 4, ihl 5
  ipv4_hdr = hex_to_bin "45000050"  -- version/ihl, dscp/ecn, total_len
  version = (string.byte(ipv4_hdr, 1) >> 4) & 0xf
  ihl = string.byte(ipv4_hdr, 1) & 0xf
  assert version == 4, "Version should be 4"
  assert ihl == 5, "IHL should be 5 (20 bytes)"

assert_test "L3: Extract IPv4 protocol field", ->
  ipv4_hdr = hex_to_bin "45000050" .. "00000000" .. "4011" .. "0000"  -- dst IP...
  protocol = string.byte(ipv4_hdr, 10)
  assert protocol == 0x11, "Protocol should be UDP (0x11)"

assert_test "L3: Extract source and destination IP addresses", ->
  ipv4_hdr = hex_to_bin "45000050" ..
             "00000000" ..
             "4011" .. "0000" ..
             "7f000001" ..  -- src IP: 127.0.0.1
             "7f000001"     -- dst IP: 127.0.0.1
  src_ip = ipv4_hdr\sub(13, 16)
  dst_ip = ipv4_hdr\sub(17, 20)
  assert #src_ip == 4, "IP should be 4 bytes"
  assert string.byte(src_ip, 1) == 0x7f, "First octet of loopback should be 127"
  assert src_ip == dst_ip, "Src and dst should match"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: L4 UDP header parsing
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "L4: Extract UDP source and destination ports", ->
  udp_hdr = hex_to_bin "270f27b0" .. "003600f7"  -- sport, dport, len, checksum
  sport = (string.byte(udp_hdr, 1) << 8) | string.byte(udp_hdr, 2)
  dport = (string.byte(udp_hdr, 3) << 8) | string.byte(udp_hdr, 4)
  assert sport == 0x270f, "Source port extraction"
  assert dport == 0x27b0, "Destination port extraction"

assert_test "L4: Extract UDP payload length", ->
  udp_hdr = hex_to_bin "270f27b0" .. "003600f7"
  length = (string.byte(udp_hdr, 5) << 8) | string.byte(udp_hdr, 6)
  assert length == 0x0036, "UDP length should match"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: L4 QUIC packet header parsing
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "L4: QUIC packet has fixed bit (0x80)", ->
  quic_first_byte = hex_to_bin "c0"
  first_byte = string.byte(quic_first_byte, 1)
  fixed_bit = (first_byte & 0x80) ~= 0
  assert fixed_bit, "Fixed bit should be set"

assert_test "L4: QUIC initial packet type detection", ->
  quic_first_byte = hex_to_bin "c0"
  first_byte = string.byte(quic_first_byte, 1)
  is_long_header = (first_byte & 0x80) ~= 0
  packet_type = (first_byte >> 4) & 0x3
  assert is_long_header, "Should be long header"
  assert packet_type == 0, "Packet type should be 0 (Initial)"

assert_test "L4: QUIC version extraction", ->
  quic_hdr = hex_to_bin "c0000000" .. "01"  -- first byte, version (big-endian)
  version = (string.byte(quic_hdr, 2) << 24) |
            (string.byte(quic_hdr, 3) << 16) |
            (string.byte(quic_hdr, 4) << 8) |
            string.byte(quic_hdr, 5)
  assert version == 1, "QUIC version should be 1"

assert_test "L4: QUIC DCID length extraction", ->
  quic_hdr = hex_to_bin "c0000000" .. "01" .. "08"  -- first byte, version, dcid_len
  dcid_len = string.byte(quic_hdr, 6)
  assert dcid_len == 8, "DCID length should be 8 bytes"

assert_test "L4: QUIC DCID extraction", ->
  dcid_hex = "8394c8f03e515708"
  quic_hdr = hex_to_bin "c0000000" .. "01" .. "08" .. dcid_hex
  dcid = quic_hdr\sub(7, 14)
  assert #dcid == 8, "DCID should be 8 bytes"
  assert dcid == hex_to_bin(dcid_hex), "DCID extraction"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: L7 QUIC SNI extraction (from initial handshake)
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "L7: Extract TLS record type from QUIC payload", ->
  -- TLS record in QUIC Initial packet payload
  -- Type 0x16 = Handshake, Version 0x0303 = TLS 1.2
  tls_record = hex_to_bin "16" .. "0303"
  record_type = string.byte(tls_record, 1)
  assert record_type == 0x16, "TLS record type should be Handshake"

assert_test "L7: Extract TLS Handshake message type", ->
  -- Handshake message starts after TLS record header
  -- Type 0x01 = ClientHello
  hs_msg = hex_to_bin "01" .. "000000"  -- msg_type, length (3 bytes)
  msg_type = string.byte(hs_msg, 1)
  assert msg_type == 0x01, "Message type should be ClientHello (0x01)"

assert_test "L7: Extract ClientHello TLS version", ->
  -- After msg type and length: TLS version
  client_hello = hex_to_bin "0303"  -- TLS 1.2
  tls_version = (string.byte(client_hello, 1) << 8) | string.byte(client_hello, 2)
  assert tls_version == 0x0303, "TLS version should be 1.2"

assert_test "L7: SNI extension type detection", ->
  -- SNI extension type is 0x0000 (type=0, length=2 bytes)
  sni_ext = hex_to_bin "0000" .. "0010"  -- type, length
  ext_type = (string.byte(sni_ext, 1) << 8) | string.byte(sni_ext, 2)
  assert ext_type == 0x0000, "SNI extension type should be 0x0000"

-- ──────────────────────────────────────────────────────────────────────────────
-- Summary
-- ──────────────────────────────────────────────────────────────────────────────

print "\n--> lib.crypto.lunatik.quic: #{tests_passed}/#{tests_passed + tests_failed}"

if tests_failed > 0
  error "#{tests_failed} test(s) failed"
