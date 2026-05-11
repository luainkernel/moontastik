--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/crypto/test_ffi_wolfssl.moon
-- Tests for the wolfSSL FFI crypto backend.
-- All tests are skipped if libwolfssl.so is not available.

util = require "ipparse.lib.util"
{:test, :summary} = util
{:hex_to_bin} = require "ipparse.lib.hkdf"

bin2hex = (s) -> s\gsub ".", (c) -> string.format "%02x", c\byte!

-- Attempt to load the backend; skip all if unavailable.
ok, b = pcall require, "ipparse.lib.crypto.backend.ffi_wolfssl"
unless ok
  test "ffi_wolfssl: backend not available (skipped)", -> true
  summary "lib.crypto.ffi_wolfssl"
  return

-- AES-128-GCM: RFC 8452 / NIST vectors (zero key, zero nonce, empty plaintext).
-- AES-128-GCM(key=0^16, nonce=0^12, pt="", aad="") → tag = 58e2fccefa7e3061367f1d57a4e7455a
test "ffi_wolfssl: GCM encrypt empty plaintext (NIST)", ->
  key   = string.rep "\x00", 16
  nonce = string.rep "\x00", 12
  ct    = b.aes_128_gcm_encrypt key, nonce, "", ""
  assert #ct == 16, "ciphertext should be 16-byte tag only"
  assert bin2hex(ct) == "58e2fccefa7e3061367f1d57a4e7455a",
    "tag mismatch: #{bin2hex ct}"

test "ffi_wolfssl: GCM decrypt empty plaintext (NIST)", ->
  key   = string.rep "\x00", 16
  nonce = string.rep "\x00", 12
  tag   = hex_to_bin "58e2fccefa7e3061367f1d57a4e7455a"
  pt, err = b.aes_128_gcm_decrypt key, nonce, tag, ""
  assert pt == "", "plaintext should be empty, got: #{tostring err}"

test "ffi_wolfssl: GCM encrypt/decrypt round-trip", ->
  key   = string.rep "\x42", 16
  nonce = string.rep "\x00", 12
  plain = "hello, wolfssl!!"   -- 16 bytes
  ct    = b.aes_128_gcm_encrypt key, nonce, plain, "aad-data"
  pt, err = b.aes_128_gcm_decrypt key, nonce, ct, "aad-data"
  assert pt == plain, "round-trip failed: #{tostring err}"

test "ffi_wolfssl: GCM decrypt fails on bad tag", ->
  key   = string.rep "\x00", 16
  nonce = string.rep "\x00", 12
  tag   = string.rep "\xff", 16
  pt, err = b.aes_128_gcm_decrypt key, nonce, tag, ""
  assert pt == nil, "should return nil on bad tag"
  assert err ~= nil, "should return error message"

test "ffi_wolfssl: GCM decrypt fails on tampered AAD", ->
  key   = string.rep "\x42", 16
  nonce = string.rep "\x00", 12
  ct    = b.aes_128_gcm_encrypt key, nonce, "test data...!!!!", "correct-aad"
  pt, err = b.aes_128_gcm_decrypt key, nonce, ct, "wrong-aad"
  assert pt == nil, "should fail with wrong AAD"

-- AES-128-ECB: RFC 9001 §A.2 header-protection vector.
-- AES-128-ECB(key=9f50449e..., block=d1b1c98d...) → 437b9aec36...
test "ffi_wolfssl: ECB RFC 9001 §A.2 header-protection mask", ->
  hp     = hex_to_bin "9f50449e04a0e810283a1e9933adedd2"
  sample = hex_to_bin "d1b1c98dd7689fb8ec11d242b123dc9b"
  mask   = b.aes_128_ecb_block hp, sample
  assert #mask == 16, "mask must be 16 bytes"
  assert bin2hex(mask)\sub(1, 10) == "437b9aec36",
    "first 5 bytes mismatch: #{bin2hex(mask)\sub 1, 10}"

test "ffi_wolfssl: ECB known NIST vector (key=0^16, block=0^16)", ->
  key   = string.rep "\x00", 16
  block = string.rep "\x00", 16
  out   = b.aes_128_ecb_block key, block
  -- AES-128-ECB(0^16, 0^16) = 66e94bd4ef8a2c3b884cfa59ca342b2e
  assert bin2hex(out) == "66e94bd4ef8a2c3b884cfa59ca342b2e",
    "NIST ECB mismatch: #{bin2hex out}"

-- construct_nonce: same logic as OpenSSL backend.
test "ffi_wolfssl: construct_nonce pn=0 returns iv unchanged", ->
  iv = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  assert b.construct_nonce(iv, 0) == iv, "nonce should equal iv when pn=0"

test "ffi_wolfssl: construct_nonce pn=1 XORs last byte", ->
  iv    = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  nonce = b.construct_nonce iv, 1
  assert nonce\sub(1, 11) == iv\sub(1, 11), "first 11 bytes unchanged"
  assert nonce\byte(12) == 0x5d, "last byte 0x5c XOR 0x01 = 0x5d"

test "ffi_wolfssl: construct_nonce pn=0x0102 XORs last two bytes", ->
  iv    = string.rep "\x00", 12
  nonce = b.construct_nonce iv, 0x0102
  assert nonce\byte(11) == 0x01, "byte 11 should be 0x01"
  assert nonce\byte(12) == 0x02, "byte 12 should be 0x02"

summary "lib.crypto.ffi_wolfssl"
