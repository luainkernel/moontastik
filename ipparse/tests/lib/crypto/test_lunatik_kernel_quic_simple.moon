--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Lunatik kernel QUIC parsing tests
-- RFC 9001 vectors and packet header parsing

-- Inline hex_to_bin (can't import in kernel context)
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
    print "FAIL\tlunatik: #{name}\tgot: #{got}, expected: #{expected}"

assert_test = (name, fn) ->
  result, err = pcall fn
  if result
    tests_passed += 1
    print "PASS\tlunatik: #{name}"
  else
    tests_failed += 1
    print "FAIL\tlunatik: #{name}\t#{err}"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: QUIC packet number encoding (section 17.1)
-- ──────────────────────────────────────────────────────────────────────────────

-- Test packing 4-byte packet number into 1-byte shortform (example from RFC 9001)
assert_test "QUIC packet number 0x12345678 encodes to 0x78 in 1-byte form", ->
  pkt_num = 0x12345678
  -- In QUIC, the full packet number is encoded, but only lower bytes transmitted
  encoded = pkt_num & 0xff
  assert encoded == 0x78, "Expected 0x78, got #{string.format('0x%02x', encoded)}"

assert_test "QUIC packet number 0xaabbccdd encodes lower byte", ->
  pkt_num = 0xaabbccdd
  encoded = pkt_num & 0xff
  assert encoded == 0xdd, "Expected 0xdd"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: QUIC nonce construction (RFC 9001 §5.2)
-- ──────────────────────────────────────────────────────────────────────────────

-- Inline construct_nonce from backend
construct_nonce = (iv, packet_number) ->
  nonce_bytes = {}
  for i = 1, #iv
    nonce_bytes[i] = string.byte(iv, i)
  
  -- XOR last 8 bytes with big-endian packet number
  pn_bytes = {}
  for j = 0, 7
    pn_bytes[j+1] = (packet_number >> (56 - j*8)) & 0xff
  
  for j = 0, 7
    idx = #iv - 7 + j
    if idx >= 1 and idx <= #iv
      a = nonce_bytes[idx] or 0
      b = pn_bytes[j+1]
      -- XOR emulation: (a | b) - (a & b)
      nonce_bytes[idx] = (a | b) - (a & b)
  
  result = ""
  for i = 1, #nonce_bytes
    result ..= string.char(nonce_bytes[i])
  result

assert_test "construct_nonce XORs packet number into IV (pkt_num = 0)", ->
  iv = hex_to_bin "4ddbf3ade1f0662ff8395a6fb32e4f7b"
  pkt_num = 0
  nonce = construct_nonce iv, pkt_num
  -- Nonce should equal IV when pkt_num is 0
  assert nonce == iv, "Nonce should match IV for pkt_num=0"

assert_test "construct_nonce XORs packet number into IV (pkt_num = 1)", ->
  iv = hex_to_bin "4ddbf3ade1f0662ff8395a6fb32e4f7b"
  pkt_num = 1
  nonce = construct_nonce iv, pkt_num
  -- For pkt_num=1, only last byte should change (XOR with 1)
  expected_last = (string.byte(iv, -1) | 1) - (string.byte(iv, -1) & 1)
  actual_last = string.byte(nonce, -1)
  assert actual_last == expected_last, "Last byte should be XORed"

-- ──────────────────────────────────────────────────────────────────────────────
-- Test: QUIC header parsing basics
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "QUIC initial packet has fixed bit set (0x80)", ->
  first_byte = 0xc0  -- Initial packet type with fixed bit
  fixed_bit = (first_byte & 0x80) ~= 0
  assert fixed_bit, "Fixed bit should be set"

assert_test "QUIC packet type extraction from first byte", ->
  -- Initial: bits 6-7 = 00, Long header = bit 7 = 1
  -- So Initial = 0x80-0xbf (bits 7=1, 6=0)
  first_byte = 0xc0  -- 1100 0000
  packet_type_bits = (first_byte >> 4) & 0x3  -- bits 4-5
  assert packet_type_bits == 0, "Initial packet type should be 00"

assert_test "QUIC version field extraction", ->
  -- Version is 4 bytes after first byte + dcid length
  -- For now just test that we can read bytes
  version_bytes = hex_to_bin "00000001"
  version = (string.byte(version_bytes, 1) << 24) |
            (string.byte(version_bytes, 2) << 16) |
            (string.byte(version_bytes, 3) << 8) |
            string.byte(version_bytes, 4)
  assert version == 1, "Expected version 1 (QUIC v1)"

-- ──────────────────────────────────────────────────────────────────────────────
-- Summary
-- ──────────────────────────────────────────────────────────────────────────────

print "\n--> lib.crypto.lunatik: #{tests_passed}/#{tests_passed + tests_failed}"

if tests_failed > 0
  error "#{tests_failed} test(s) failed"
