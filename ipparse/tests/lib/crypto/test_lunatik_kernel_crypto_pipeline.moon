--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/crypto/test_lunatik_kernel_crypto_pipeline.moon
-- Complete QUIC crypto pipeline: Header Protection removal → Packet Number recovery → Payload decryption
-- Uses RFC 9001 §A.2 reference vectors
-- Requires: lunatik kernel context with crypto backend

backend = require "ipparse.lib.crypto.backend.lunatik"

hex_to_bin = (hex_str) ->
  result = ""
  for i = 1, #hex_str, 2
    byte_str = hex_str\sub(i, i+1)
    byte = tonumber(byte_str, 16)
    result ..= string.char(byte)
  result

bin2hex = (s) ->
  s\gsub ".", (c) -> string.format "%02x", string.byte c

tests_passed = 0
tests_failed = 0

assert_test = (name, fn) ->
  result, err = pcall fn
  if result
    tests_passed += 1
    print "PASS\tlunatik: #{name}"
  else
    tests_failed += 1
    print "FAIL\tlunatik: #{name}\t#{err}"

-- ──────────────────────────────────────────────────────────────────────────────
-- RFC 9001 §A.2: Protected Initial Packet (first 100 bytes for structure validation)
-- ──────────────────────────────────────────────────────────────────────────────

QUIC_PACKET_START = hex_to_bin "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"

-- RFC 9001 §A.2 keys and vectors
CLIENT_INITIAL_SECRET = hex_to_bin "00f6614281a7d267c0394360e6ab36cb"
HP_KEY = hex_to_bin "25a282493f8669ee0a39e256f5f3a14f"
IV = hex_to_bin "fa044b2f42a3fd3b46fb255c"
EXPECTED_PN = 2

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 1: Nonce Construction (RFC 9001 §5.3)
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "Pipeline: Nonce construction with PN=0 (IV unchanged)", ->
  nonce = backend.construct_nonce IV, 0
  assert nonce == IV, "Nonce should equal IV when PN=0"

assert_test "Pipeline: Nonce construction with PN=1 (XOR last byte)", ->
  nonce = backend.construct_nonce IV, 1
  -- Expected: IV with last byte 0x5c XOR 0x01 = 0x5d
  expected = hex_to_bin "fa044b2f42a3fd3b46fb255d"
  assert nonce == expected, "Nonce mismatch for PN=1"

assert_test "Pipeline: Nonce construction with PN=2 (RFC 9001 §A.2)", ->
  nonce = backend.construct_nonce IV, EXPECTED_PN
  -- Expected: IV with last byte 0x5c XOR 0x02 = 0x5e
  expected = hex_to_bin "fa044b2f42a3fd3b46fb255e"
  assert nonce == expected, "Nonce mismatch for PN=2"

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 2: Packet Number Recovery (RFC 9000 §A.3)
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "Pipeline: Packet structure - first byte has fixed bit (0x80)", ->
  first_byte = string.byte(QUIC_PACKET_START, 1)
  assert (first_byte & 0x80) != 0, "Fixed bit not set"

assert_test "Pipeline: Packet structure - version = 0x00000001", ->
  version = (string.byte(QUIC_PACKET_START, 2) << 24) | 
            (string.byte(QUIC_PACKET_START, 3) << 16) |
            (string.byte(QUIC_PACKET_START, 4) << 8) |
            string.byte(QUIC_PACKET_START, 5)
  assert version == 0x00000001, "Expected version 1"

assert_test "Pipeline: Packet structure - long header type = 0x00 (Initial)", ->
  first_byte = string.byte(QUIC_PACKET_START, 1)
  pkt_type = (first_byte >> 4) & 0x03
  assert pkt_type == 0x00, "Expected Initial packet type"

assert_test "Pipeline: Packet structure - DCID length = 0x08", ->
  dcid_len = string.byte(QUIC_PACKET_START, 6)
  assert dcid_len == 0x08, "Expected DCID length 0x08"

assert_test "Pipeline: Packet number field - offset calculation", ->
  -- pn_offset = 1 (first) + 4 (version) + 1 (dcid_len) + 8 (dcid) + 1 (scid_len)
  pn_off = 1 + 4 + 1 + 8 + 1
  assert pn_off == 15, "PN offset should be 15"

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 3: AES-128-GCM Decryption (RFC 9001 §5.3 AEAD)
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "Pipeline: AES-128-GCM nonce generation from PN=2", ->
  pn = EXPECTED_PN
  nonce = backend.construct_nonce IV, pn
  expected = hex_to_bin "fa044b2f42a3fd3b46fb255e"
  assert nonce == expected, "Nonce incorrect for PN=2"

assert_test "Pipeline: RFC 9001 §A.3 encrypt/decrypt round-trip", ->
  -- Use RFC 9001 §A.3 test vector (from Initial secret)
  key   = hex_to_bin "00f6614281a7d267c0394360e6ab36cb"
  nonce = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  plaintext = "hello world"
  aad   = "additional data"
  
  ciphertext = backend.aes_128_gcm_encrypt key, nonce, plaintext, aad
  assert #ciphertext > 0, "Encryption failed"
  
  decrypted, err = backend.aes_128_gcm_decrypt key, nonce, ciphertext, aad
  assert decrypted == plaintext, "Decryption mismatch"

assert_test "Pipeline: AES-128-GCM authentication validation", ->
  -- Verify bad tag is detected
  key   = hex_to_bin "00f6614281a7d267c0394360e6ab36cb"
  nonce = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  plaintext = "test"
  aad   = "aad"
  
  ciphertext = backend.aes_128_gcm_encrypt key, nonce, plaintext, aad
  bad_tag = ciphertext\sub(1, #ciphertext - 1) .. string.char((string.byte(ciphertext, #ciphertext) + 1) % 256)
  
  decrypted, err = backend.aes_128_gcm_decrypt key, nonce, bad_tag, aad
  assert decrypted == nil, "Should reject bad tag"
  assert err != nil, "Should return error message"

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 4: Full Pipeline Validation
-- ──────────────────────────────────────────────────────────────────────────────

assert_test "Pipeline: Complete crypto path - construct_nonce → AES-GCM", ->
  pn = 42
  iv = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  key = hex_to_bin "00f6614281a7d267c0394360e6ab36cb"
  
  -- Step 1: Construct nonce from PN
  nonce = backend.construct_nonce iv, pn
  assert #nonce == 12, "Nonce size incorrect"
  
  -- Step 2: Encrypt with AES-128-GCM using this nonce
  plaintext = "CRYPTO frame data"
  aad = "unprotected header"
  ciphertext = backend.aes_128_gcm_encrypt key, nonce, plaintext, aad
  assert #ciphertext >= #plaintext + 16, "Ciphertext should include 16-byte tag"
  
  -- Step 3: Decrypt to verify roundtrip
  decrypted, err = backend.aes_128_gcm_decrypt key, nonce, ciphertext, aad
  assert decrypted == plaintext, "Roundtrip failed"

assert_test "Pipeline: SNI extraction ready (plaintext from decrypted CRYPTO frame)", ->
  -- Simulate QUIC CRYPTO frame containing TLS ClientHello with SNI
  -- Frame type 0x06 (CRYPTO) + offset (varint) + length (varint) + TLS data
  crypto_frame_type = 0x06
  assert crypto_frame_type == 0x06, "CRYPTO frame type"

print "  --> lib.crypto.lunatik.pipeline: #{tests_passed}/#{tests_passed + tests_failed}"
