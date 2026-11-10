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

-- EBADMSG error names produced by Lunatik's lunatik_pusherrname
-- (lunatik_aux.c, kernel >= 6.7): errname(abs(err)) == "EBADMSG".
-- On older kernels it formats "%pE" of ERR_PTR(-err): with
-- CONFIG_SYMBOLIC_ERRNAME this is errname(-err) == "-EBADMSG"
-- (lib/errname.c), otherwise the signed decimal "-74" (EBADMSG == 74,
-- include/uapi/asm-generic/errno.h), see lib/vsprintf.c err_ptr().
ebadmsg_names = { EBADMSG: true, ["-EBADMSG"]: true, ["-74"]: true }

--- Checks whether an error value denotes EBADMSG.
-- Compares the whole string so digits embedded in other errnos (e.g. -174)
-- are not matched. Lua's error() prepends "chunk:line: "; Lunatik's
-- lunatik_throw() calls lua_error() directly, without such a prefix.
-- @tparam string err Error value
-- @treturn boolean true if the error is EBADMSG
is_ebadmsg = (err) ->
  s = tostring err
  bare = (s\match "^.*:%d+: (.*)$") or s
  ebadmsg_names[bare] == true

--- Normalizes an EBADMSG from either Lunatik convention to the public error.
-- @tparam string err Error value (name, "-NAME" or signed decimal)
-- @treturn string|nil Authentication error message, or nil if not EBADMSG
ebadmsg_error = (err) ->
  return unless is_ebadmsg err
  "AES-128-GCM authentication failed (tag mismatch)"

gcm_cache = {encrypt: {}, decrypt: {}}
cached_ecb_tfm = nil
cached_ecb_key = nil
ecb_fail_streak = 0

get_gcm_tfm = (mode, key) ->
  entry = gcm_cache[mode]
  unless entry.tfm
    entry.tfm = aead "gcm(aes)"
    entry.tfm\setauthsize 16
  if entry.key != key
    entry.tfm\setkey key
    entry.key = key
  entry.tfm

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
  -- Two Lunatik conventions must be handled:
  --   * old API (fork fix_crypto_enomem): decrypt raises (lunatik_throw) on
  --     bad tag, so the error lands in the pcall status slot;
  --   * upstream v5.1+ (lib/luacrypto_aead.c: luacrypto_aead_decrypt calls
  --     lunatik_pushfail(L, -EBADMSG)): decrypt returns nil, "EBADMSG" and
  --     nothing is raised. Only non-EBADMSG failures still raise.
  ok, pt, err = pcall c.decrypt, c, nonce, ciphertext_with_tag, aad
  unless ok
    msg = ebadmsg_error pt
    return nil, msg if msg
    return nil, "aead(gcm(aes)) decrypt failed: #{tostring pt}"
  -- Success returns the plaintext (possibly ""); only inspect the second
  -- value when the plaintext is nil (a plaintext equal to "EBADMSG" is kept).
  if pt == nil
    msg = ebadmsg_error err
    return nil, msg if msg
    return nil, "aead(gcm(aes)) decrypt failed: #{tostring err}"
  pt, nil

--- Encrypts single AES-128-ECB block.
-- Uses a cached skcipher transform to avoid frequent allocations under load.
-- Returns nil on failure so caller can defer processing and retry later.
-- @tparam string key 16-byte key
-- @tparam string block 16-byte plaintext block
-- @treturn string 16-byte ciphertext block, or nil if ECB unavailable
ecb_encrypt = (key, block) ->
  unless cached_ecb_tfm
    cached_ecb_tfm = skcipher "ecb(aes)"
    cached_ecb_key = nil
  if cached_ecb_key != key
    cached_ecb_tfm\setkey key
    cached_ecb_key = key
  -- ECB doesn't use IV, but skcipher API requires it
  -- For ECB, ivsize should be 0, so we pass empty string
  cached_ecb_tfm\encrypt "", block

aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  ok, result = pcall ecb_encrypt, key, block
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
