--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Lunatik crypto backend for ipparse (no FFI).
--
-- Implements the ipparse crypto interface using Lunatik's kernel `crypto` Lua API.
-- Requires a Lunatik runtime with:
--   - require("crypto").aead       (for AES-128-GCM)
--   - require("crypto").skcipher  (for AES-128-ECB, ephemeral allocation)
--
-- Implements:
--   aes_128_gcm_encrypt(key, nonce, plaintext, aad) → ciphertext_with_tag
--   aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad) → plaintext | nil, err
--   aes_128_ecb_block(key, block) → encrypted_block (with fallback)
--
-- Note: ECB uses skcipher with ephemeral allocation to avoid persistent memory pressure.
-- If ECB fails, returns nil so caller can skip this packet and retry later.
--
-- @module lib.crypto.backend.lunatik

{:aead, :skcipher} = require "crypto"
{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :construct_nonce} = require "ipparse.lib.crypto.backend.common"

close_tfm = (tfm) ->
  return unless tfm and tfm.__close
  pcall tfm.__close, tfm

cached_gcm_enc_tfm = nil
cached_gcm_enc_key = nil
cached_gcm_dec_tfm = nil
cached_gcm_dec_key = nil
cached_ecb_tfm = nil
cached_ecb_key = nil
ecb_fail_streak = 0

get_gcm_tfm = (mode, key) ->
  if mode == "encrypt"
    unless cached_gcm_enc_tfm
      cached_gcm_enc_tfm = aead "gcm(aes)"
      cached_gcm_enc_tfm\setauthsize 16
    if cached_gcm_enc_key != key
      cached_gcm_enc_tfm\setkey key
      cached_gcm_enc_key = key
    return cached_gcm_enc_tfm
  else
    unless cached_gcm_dec_tfm
      cached_gcm_dec_tfm = aead "gcm(aes)"
      cached_gcm_dec_tfm\setauthsize 16
    if cached_gcm_dec_key != key
      cached_gcm_dec_tfm\setkey key
      cached_gcm_dec_key = key
    return cached_gcm_dec_tfm

--- Encrypts with AES-128-GCM.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext Data to encrypt
-- @tparam string aad Additional authenticated data (optional)
-- @treturn string ciphertext || tag (16 bytes appended to ciphertext)
aes_128_gcm_encrypt = (key, nonce, plaintext, aad = "") ->
  validate_gcm_key key
  validate_gcm_nonce nonce
  c = get_gcm_tfm "encrypt", key
  out = c\encrypt nonce, plaintext, aad
  out

--- Decrypts with AES-128-GCM.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string ciphertext_with_tag Ciphertext with 16-byte tag appended
-- @tparam string aad Additional authenticated data (optional)
-- @treturn string plaintext on success, or nil on authentication failure
-- @treturn string error message on failure
aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad = "") ->
  validate_gcm_key key
  validate_gcm_nonce nonce
  if #ciphertext_with_tag < 16
    return nil, "ciphertext_with_tag too short (need at least 16-byte tag)"
  c = get_gcm_tfm "decrypt", key
  -- Wrap decrypt call to catch EBADMSG as a handled error, not an exception
  ok, pt_or_err, err = pcall -> c\decrypt nonce, ciphertext_with_tag, aad
  unless ok
    -- Decrypt failed with Lua error
    if (tostring pt_or_err)\match "EBADMSG"
      return nil, "AES-128-GCM authentication failed (tag mismatch)"
    return nil, "aead(gcm(aes)) decrypt failed: #{tostring pt_or_err}"
  -- ok=true, pt_or_err is plaintext, err is error code
  if pt_or_err == "EBADMSG"
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  -- pt_or_err is plaintext (may be empty string, which is valid)
  pt_or_err, nil

--- Encrypts single AES-128-ECB block.
-- Uses a cached skcipher transform to avoid frequent allocations under load.
-- Returns nil on failure so caller can defer processing and retry later.
-- @tparam string key 16-byte key
-- @tparam string block 16-byte plaintext block
-- @treturn string 16-byte ciphertext block, or nil if ECB unavailable
aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  ok, result = pcall ->
    unless cached_ecb_tfm
      cached_ecb_tfm = skcipher "ecb(aes)"
      cached_ecb_key = nil
    if cached_ecb_key != key
      cached_ecb_tfm\setkey key
      cached_ecb_key = key
    -- ECB doesn't use IV, but skcipher API requires it
    -- For ECB, ivsize should be 0, so we pass empty string
    cached_ecb_tfm\encrypt "", block
  unless ok
    -- Keep cached tfm/key to avoid churn under memory pressure.
    -- Reallocating tfm on each transient failure tends to make ENOMEM worse.
    ecb_fail_streak += 1
    if ecb_fail_streak == 1 or ecb_fail_streak % 128 == 0
      print "WARN: aes_128_ecb_block unavailable (#{result}), header protection temporarily skipped [#{ecb_fail_streak}]"
    return nil
  ecb_fail_streak = 0
  result

{
  :aes_128_gcm_encrypt
  :aes_128_gcm_decrypt
  :aes_128_ecb_block
  :construct_nonce
}
