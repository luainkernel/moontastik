--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/crypto/test_lunatik.moon
-- Tests for the Lunatik crypto backend (without FFI).
-- These tests stub require("crypto") so they run in userland too.

util = require "ipparse.lib.util"
{:test, :summary} = util
{:hex_to_bin} = require "ipparse.lib.hkdf"

-- Snapshot package state before installing the stubs below, so nothing leaks
-- into the modules loaded after this one in the same test run.
preload_before = {
  crypto: package.preload.crypto
  crypto_ecb: package.preload["crypto.ecb"]
}
loaded_before = {
  crypto: package.loaded["crypto"]
  crypto_ecb: package.loaded["crypto.ecb"]
  backend: package.loaded["ipparse.lib.crypto.backend.lunatik"]
}
loaded_keys_before = {}
for k in pairs package.loaded
  loaded_keys_before[k] = true

calls = {
  aead_new: 0
  aead_close: 0
  ecb_new: 0
  ecb_close: 0
}

mk_aead = ->
  key, authsize = nil, nil
  {
    setkey: (k) => key = k
    setauthsize: (n) => authsize = n
    encrypt: (nonce, plaintext, aad="") =>
      assert key == string.rep("\017", 16), "unexpected test key"
      assert authsize == 16, "authsize must be 16"
      assert #nonce == 12, "nonce length should be 12"
      "ct:" .. plaintext .. "|aad:" .. aad .. "|tag:" .. string.rep("T", 16)
    decrypt: (nonce, ciphertext_with_tag, aad="") =>
      prefix = ciphertext_with_tag\sub 1, 8
      if prefix == "AUTHFAIL"
        error "EBADMSG"
      if prefix == "AUTHMIN1"
        error "-EBADMSG"
      if prefix == "AUTHNUM1"
        error "-74"
      if prefix == "AUTHNUM3"
        error "-174"
      if prefix == "AUTHNUM4"
        error "-740"
      if prefix == "NOTAUTH2"
        error "-22"
      if ciphertext_with_tag\sub(1, 6) == "BROKEN"
        error "EINVAL"
      if prefix == "PLAINBAD"
        return "EBADMSG"
      -- Upstream Lunatik v5.1 convention (luacrypto_aead_decrypt ->
      -- lunatik_pushfail): return nil, <errname> instead of raising.
      if prefix == "NEWFAIL1"
        return nil, "EBADMSG"
      if prefix == "NEWFAIL2"
        return nil, "-EBADMSG"
      if prefix == "NEWFAIL3"
        return nil, "-74"
      if prefix == "NEWFAIL4"
        return nil, "unknown"
      if prefix == "NEWERR01"
        return nil, "EINVAL"
      if prefix == "NEWERR02"
        return nil, "-174"
      "pt:" .. ciphertext_with_tag .. "|aad:" .. aad
    __close: =>
      calls.aead_close += 1
  }

mk_ecb = ->
  key = nil
  {
    setkey: (k) => key = k
    encrypt: (iv, block) =>
      assert key == string.rep("\034", 16), "unexpected ECB key"
      assert iv == "", "ECB expects an empty IV"
      assert #block == 16, "ECB block must be 16 bytes"
      "Z" .. block\sub(2)
    __close: =>
      calls.ecb_close += 1
  }

package.preload.crypto = ->
  {
    aead: (name) ->
      assert name == "gcm(aes)", "unexpected AEAD algorithm: #{name}"
      calls.aead_new += 1
      mk_aead!
    skcipher: (name) ->
      assert name == "ecb(aes)", "unexpected skcipher algorithm: #{name}"
      calls.ecb_new += 1
      mk_ecb!
  }

package.loaded["ipparse.lib.crypto.backend.lunatik"] = nil
b = require "ipparse.lib.crypto.backend.lunatik"

test "lunatik: construct_nonce pn=0 returns iv unchanged", ->
  iv = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  assert b.construct_nonce(iv, 0) == iv, "nonce should equal iv when pn=0"

test "lunatik: construct_nonce pn=1 XORs last byte", ->
  iv    = hex_to_bin "fa044b2f42a3fd3b46fb255c"
  nonce = b.construct_nonce iv, 1
  assert nonce\sub(1, 11) == iv\sub(1, 11), "first 11 bytes unchanged"
  assert nonce\byte(12) == 0x5d, "last byte 0x5c XOR 0x01 = 0x5d"

test "lunatik: AES-128-GCM encrypt uses crypto.aead", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  out = b.aes_128_gcm_encrypt key, nonce, "hello", "aad"
  assert out == ("ct:hello|aad:aad|tag:" .. string.rep("T", 16)), "unexpected ciphertext"

test "lunatik: AES-128-GCM decrypt returns plaintext", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("cipher" .. string.rep("T", 16)), "aad"
  assert err == nil, "unexpected decrypt error: #{tostring err}"
  assert pt == ("pt:cipher" .. string.rep("T", 16) .. "|aad:aad"), "unexpected plaintext"

test "lunatik: AES-128-GCM decrypt maps EBADMSG to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHFAIL" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps -EBADMSG (pre-6.7 symbolic) to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHMIN1" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps -74 (pre-6.7 numeric) to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHNUM1" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps v5.1 nil,EBADMSG to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWFAIL1" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps v5.1 nil,-EBADMSG to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWFAIL2" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps v5.1 nil,-74 to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWFAIL3" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps v5.1 nil,unknown to decrypt failed", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWFAIL4" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps v5.1 nil,EINVAL to decrypt failed", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWERR01" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt does not treat v5.1 nil,-174 as EBADMSG", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NEWERR02" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt does not treat -174 as EBADMSG", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHNUM3" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt does not treat -740 as EBADMSG", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHNUM4" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt maps -22 (numeric EINVAL) to nil,error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("NOTAUTH2" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on failure"
  assert err ~= "AES-128-GCM authentication failed (tag mismatch)", "unexpected auth error: #{tostring err}"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM decrypt returns plaintext equal to EBADMSG verbatim", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("PLAINBAD" .. string.rep("T", 16)), ""
  assert err == nil, "unexpected decrypt error: #{tostring err}"
  assert pt == "EBADMSG", "plaintext should be returned verbatim, got: #{tostring pt}"

test "lunatik: AES-128-GCM ciphertext too short returns nil", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, "short", ""
  assert pt == nil, "pt should be nil"
  assert err ~= nil, "err should be provided"

test "lunatik: AES-128-GCM decrypt returns nil,error on non-auth error", ->
  key = string.rep "\017", 16
  nonce = string.rep "\000", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("BROKEN" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on non-auth failure"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-ECB encrypt uses crypto.skcipher", ->
  key = string.rep "\034", 16
  block = string.rep "\051", 16
  out = b.aes_128_ecb_block key, block
  assert #out == 16, "output must be 16 bytes"
  assert out\byte(1) == string.byte("Z"), "first byte should be transformed by stub"

-- Restore package state altered by the stubs above.
leaked = {}
for k in pairs package.loaded
  leaked[#leaked + 1] = k unless loaded_keys_before[k]
for k in *leaked
  package.loaded[k] = nil
package.preload.crypto = preload_before.crypto
package.preload["crypto.ecb"] = preload_before.crypto_ecb
package.loaded["crypto"] = loaded_before.crypto
package.loaded["crypto.ecb"] = loaded_before.crypto_ecb
package.loaded["ipparse.lib.crypto.backend.lunatik"] = loaded_before.backend

summary "lib.crypto.lunatik"
