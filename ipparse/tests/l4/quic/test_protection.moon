--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_protection.moon
-- Tests for QUIC v1 construct_nonce and recover_packet_number.
-- The header-protection and AEAD tests require the LuaJIT FFI backend
-- (libcrypto.so) and are skipped if it cannot be loaded.

util = require "ipparse.lib.util"
{:test} = util
prot = require "ipparse.l4.quic.v1.protection"
{:hex_to_bin} = require "ipparse.lib.hkdf"

bin2hex = (s) ->
  s\gsub ".", (c) -> string.format "%02x", string.byte c

-- construct_nonce: RFC 9001 §5.3
-- iv = fa044b2f42a3fd3b46fb255c, pn = 0
-- nonce = iv XOR (0 padded) = iv unchanged
test "protection: construct_nonce with pn=0 returns iv", ->
  iv = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  nonce = prot.construct_nonce iv, 0
  assert nonce == iv, "nonce should equal iv when pn=0"

-- construct_nonce with pn=1: only last byte changes
test "protection: construct_nonce with pn=1", ->
  iv = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  nonce = prot.construct_nonce iv, 1
  -- last byte: 0x5c XOR 0x01 = 0x5d
  assert nonce\sub(1, 11) == iv\sub(1, 11), "first 11 bytes should match"
  assert string.byte(nonce, 12) == 0x5d, "last byte should be 0x5d"

-- recover_packet_number: basic cases (RFC 9000 §A.3)
test "protection: recover_packet_number 1-byte simple", ->
  -- expected_pn = 0, truncated = 0, pn_len = 1 → full = 0
  pn = prot.recover_packet_number 0, 0, 1
  assert pn == 0, "expected 0, got #{pn}"

test "protection: recover_packet_number wrap around", ->
  -- expected = 256, truncated = 0, pn_len=1 (window=256, hwin=128)
  -- candidate = (256 & ~0xFF) | 0 = 256
  -- 256 > 256 + 128? no. 256 <= 256 - 128 = 128? no. → 256
  pn = prot.recover_packet_number 0, 256, 1
  assert pn == 256, "expected 256, got #{pn}"

test "protection: recover_packet_number lower half wraps back", ->
  -- expected = 130, truncated = 5, pn_len=1 (window=256, hwin=128)
  -- candidate = (130 & ~0xFF) | 5 = 5
  -- 5 <= 130 - 128 = 2? no. 5 > 130 + 128 = 258? no. → 5
  -- Actually: candidate=5, expected=130, hwin=128 → 5 <= 2? no, 5 > 258? no → 5
  pn = prot.recover_packet_number 5, 130, 1
  assert pn == 5, "expected 5, got #{pn}"

-- sample_from_packet: offset arithmetic
test "protection: sample_from_packet 16 bytes at correct position", ->
  -- pkt = 40 zeros, enc_off = 20
  -- sample starts at 20+4=24, length 16 → bytes 24..39
  pkt = (string.rep "\x00", 20) .. (string.rep "\xFF", 20)
  sample = prot.sample_from_packet pkt, 20
  assert #sample == 16, "sample must be 16 bytes"
  -- bytes 24..39 of the packet: all 0xFF (we have 20 zeros then 20 FFs)
  -- wait: pkt[1..20]=0x00, pkt[21..40]=0xFF
  -- sample = pkt[24..39] = all 0xFF
  assert sample == string.rep("\xFF", 16), "sample bytes mismatch"

-- Backend-dependent tests (skip if libcrypto not available)
ok_backend, backend = pcall require, "ipparse.lib.crypto.backend.ffi_openssl"

if ok_backend
  -- AES-128-GCM round-trip
  test "protection: AES-128-GCM encrypt/decrypt round-trip", ->
    key   = string.rep "\x01", 16
    iv    = string.rep "\x02", 12
    plain = "Hello, QUIC!"
    aad   = "header"
    ct = backend.aes_128_gcm_encrypt key, iv, plain, aad
    pt, err = backend.aes_128_gcm_decrypt key, iv, ct, aad
    assert pt == plain, "round-trip failed: #{err}"

  test "protection: AES-128-GCM decrypt fails on bad tag", ->
    key = string.rep "\x01", 16
    iv  = string.rep "\x02", 12
    ct = backend.aes_128_gcm_encrypt key, iv, "plaintext", ""
    -- corrupt last byte (auth tag)
    bad_ct = ct\sub(1, #ct - 1) .. string.char((string.byte(ct, #ct) + 1) % 256)
    pt, err = backend.aes_128_gcm_decrypt key, iv, bad_ct, ""
    assert pt == nil, "expected nil on bad tag"
    assert err ~= nil, "expected error message"

  -- AES-128-ECB: known test vector (NIST FIPS 197 Appendix B)
  test "protection: AES-128-ECB block NIST vector", ->
    key   = hex_to_bin "2b7e151628aed2a6abf7158809cf4f3c"
    block = hex_to_bin "3243f6a8885a308d313198a2e0370734"
    out   = backend.aes_128_ecb_block key, block
    expected_hex = "3925841d02dc09fbdc118597196a0b32"
    assert bin2hex(out) == expected_hex, "AES-ECB NIST mismatch:\ngot: #{bin2hex out}"

  -- construct_nonce + AEAD: RFC 9001 §A.3 first client packet
  -- Client key: 1f369613dd76d5467730efcbe3b1a22d
  -- Client iv:  fa044b2f42a3fd3b46fb255c
  -- Packet number: 2  (the test packet in §A.3 has pn=2 after header protection removal)
  -- nonce = iv XOR 000000000000000000000002
  -- = fa044b2f42a3fd3b46fb255c XOR 000000000000000000000002
  -- = fa044b2f42a3fd3b46fb255e
  test "protection: construct_nonce matches RFC 9001 §A.3", ->
    iv    = hex_to_bin "fa044b2f42a3fd3b46fb255c"
    nonce = prot.construct_nonce iv, 2
    assert bin2hex(nonce) == "fa044b2f42a3fd3b46fb255e", "nonce mismatch: #{bin2hex nonce}"

  -- remove_header_protection: RFC 9001 §A.2 client Initial packet
  -- Protected:   first_byte=c0, pn=7b9aec34
  -- Unprotected: first_byte=c3, pn=00000002 (pn=2, pn_len=4)
  -- hp_key = 9f50449e04a0e810283a1e9933adedd2
  test "protection: remove_header_protection RFC 9001 §A.2 vector", ->
    -- Minimal packet: just enough bytes for sample extraction
    -- Header is 22 bytes (up to and including PN), then ciphertext
    -- pn_off=19 (1-based), sample at byte 23 = pkt[23..38]
    hp_key = hex_to_bin "9f50449e04a0e810283a1e9933adedd2"
    -- Build a synthetic packet: known protected header + 32 bytes of ciphertext payload
    -- protected header (bytes 1..22):
    --   byte1=c0, version=00000001, dcid_len=08, dcid=8394c8f03e515708,
    --   scid_len=00, token_len=00, length=449e, pn=7b9aec34
    hdr_hex = "c000000001088394c8f03e5157080000449e7b9aec34"
    -- sample must be bytes 23..38 of ciphertext; use RFC values:
    -- RFC §A.3: sample = d1b1c98dd7689fb8ec11d242b123dc9b
    ciphertext_hex = "d1b1c98dd7689fb8ec11d242b123dc9b" .. string.rep("00", 16)
    pkt = hex_to_bin(hdr_hex .. ciphertext_hex)
    hdr_bytes, pn, pn_len = prot.remove_header_protection pkt, 19, hp_key, true, 0, backend
    assert hdr_bytes[1] == 0xc3, "first byte should be c3, got #{string.format('%02x', hdr_bytes[1])}"
    assert pn == 2,    "packet number should be 2, got #{pn}"
    assert pn_len == 4, "pn_len should be 4, got #{pn_len}"
    -- Unprotected PN bytes should be 00 00 00 02
    assert hdr_bytes[19] == 0x00, "pn byte 0 should be 0x00"
    assert hdr_bytes[22] == 0x02, "pn byte 3 should be 0x02"

else
  -- Emit one skipped test so the runner knows these tests exist but were skipped
  test "protection: backend tests skipped (libcrypto not available)", ->
    -- not a failure, just informational
    true

util.summary "protection"
