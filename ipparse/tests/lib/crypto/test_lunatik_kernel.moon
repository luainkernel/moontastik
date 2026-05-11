--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/crypto/test_lunatik_kernel.moon
-- Real Lunatik kernel crypto test (no mocks).
-- Run with:
--   sudo make test-lunatik

backend = require "ipparse.lib.crypto.backend.lunatik"

bin2hex = (s) ->
  s\gsub ".", (c) -> string.format "%02x", string.byte c

hex_to_bin = (hex) ->
  hex\gsub "..", (cc) -> string.char tonumber cc, 16

pass = 0
total = 0

test = (name, fn) ->
  total += 1
  ok, err = pcall fn
  if ok
    pass += 1
    print "PASS\t#{name}"
    return
  print "FAIL\t#{name}\t#{err}"
  error err

test "lunatik-kernel: construct_nonce pn=2 (RFC 9001 A.3)", ->
  iv    = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  nonce = backend.construct_nonce iv, 2
  assert bin2hex(nonce) == "fa044b2f42a3fd3b46fb255e", "nonce mismatch: #{bin2hex nonce}"

test "lunatik-kernel: GCM encrypt empty plaintext (NIST)", ->
  key   = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  ct    = backend.aes_128_gcm_encrypt key, nonce, "", ""
  assert #ct == 16, "ciphertext should be 16-byte tag only"
  assert bin2hex(ct) == "58e2fccefa7e3061367f1d57a4e7455a",
    "tag mismatch: #{bin2hex ct}"

test "lunatik-kernel: GCM decrypt empty plaintext (NIST)", ->
  key   = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  tag   = hex_to_bin "58e2fccefa7e3061367f1d57a4e7455a"
  pt, err = backend.aes_128_gcm_decrypt key, nonce, tag, ""
  assert err == nil, "unexpected decrypt error: #{tostring err}"
  assert pt == "", "plaintext should be empty"

test "lunatik-kernel: GCM decrypt fails on bad tag", ->
  key   = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42"
  nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  ct    = backend.aes_128_gcm_encrypt key, nonce, "test data...!!!!", "aad"
  bad_ct = ct\sub(1, #ct - 1) .. string.char((string.byte(ct, #ct) + 1) % 256)
  pt, err = backend.aes_128_gcm_decrypt key, nonce, bad_ct, "aad"
  assert pt == nil, "expected nil on bad tag"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

print "  --> lib.crypto.lunatik.kernel: #{pass}/#{total}"
