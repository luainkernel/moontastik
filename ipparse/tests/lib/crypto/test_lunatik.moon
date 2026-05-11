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
      assert key == string.rep("\x11", 16), "unexpected test key"
      assert authsize == 16, "authsize must be 16"
      assert #nonce == 12, "nonce length should be 12"
      "ct:" .. plaintext .. "|aad:" .. aad .. "|tag:" .. string.rep("T", 16)
    decrypt: (nonce, ciphertext_with_tag, aad="") =>
      if ciphertext_with_tag\sub(1, 8) == "AUTHFAIL"
        error "EBADMSG"
      if ciphertext_with_tag\sub(1, 6) == "BROKEN"
        error "EINVAL"
      "pt:" .. ciphertext_with_tag .. "|aad:" .. aad
    __close: =>
      calls.aead_close += 1
  }

mk_ecb = ->
  key = nil
  {
    setkey: (k) => key = k
    encryptblock: (block) =>
      assert key == string.rep("\x22", 16), "unexpected ECB key"
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
  }

package.preload["crypto.ecb"] = ->
  {
    new: ->
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
  key = string.rep "\x11", 16
  nonce = string.rep "\x00", 12
  out = b.aes_128_gcm_encrypt key, nonce, "hello", "aad"
  assert out == ("ct:hello|aad:aad|tag:" .. string.rep("T", 16)), "unexpected ciphertext"

test "lunatik: AES-128-GCM decrypt returns plaintext", ->
  key = string.rep "\x11", 16
  nonce = string.rep "\x00", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("cipher" .. string.rep("T", 16)), "aad"
  assert err == nil, "unexpected decrypt error: #{tostring err}"
  assert pt == ("pt:cipher" .. string.rep("T", 16) .. "|aad:aad"), "unexpected plaintext"

test "lunatik: AES-128-GCM decrypt maps EBADMSG to nil,error", ->
  key = string.rep "\x11", 16
  nonce = string.rep "\x00", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, ("AUTHFAIL" .. string.rep("T", 16)), ""
  assert pt == nil, "pt should be nil on auth failure"
  assert err == "AES-128-GCM authentication failed (tag mismatch)", "unexpected error: #{tostring err}"

test "lunatik: AES-128-GCM ciphertext too short returns nil", ->
  key = string.rep "\x11", 16
  nonce = string.rep "\x00", 12
  pt, err = b.aes_128_gcm_decrypt key, nonce, "short", ""
  assert pt == nil, "pt should be nil"
  assert err ~= nil, "err should be provided"

test "lunatik: AES-128-GCM decrypt raises on non-auth error", ->
  key = string.rep "\x11", 16
  nonce = string.rep "\x00", 12
  ok, err = pcall b.aes_128_gcm_decrypt, key, nonce, ("BROKEN" .. string.rep("T", 16)), ""
  assert not ok, "decrypt should raise on non-auth failure"
  assert tostring(err)\find("aead(gcm(aes)) decrypt failed", 1, true), "unexpected error: #{tostring err}"

test "lunatik: AES-128-ECB encrypt uses crypto.ecb", ->
  key = string.rep "\x22", 16
  block = string.rep "\x33", 16
  out = b.aes_128_ecb_block key, block
  assert #out == 16, "output must be 16 bytes"
  assert out\byte(1) == string.byte("Z"), "first byte should be transformed by stub"

summary "lib.crypto.lunatik"
