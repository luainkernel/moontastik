--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- LuaJIT FFI crypto backend for ipparse — mbedTLS.
--
-- Implements the ipparse crypto interface using LuaJIT FFI and libmbedcrypto
-- (mbedTLS 3.x, default build config: MBEDTLS_GCM_HTABLE_SIZE = 16).
--
-- Context struct sizes are opaque upper bounds validated against the installed
-- headers (424 bytes for gcm_context, 288 bytes for aes_context).
-- If mbedTLS is compiled with MBEDTLS_GCM_LARGE_TABLE the GCM context
-- grows to ~4200 bytes; in that case the GCM_CTX_SIZE constant below must
-- be raised accordingly.
--
-- Implements:
--   construct_nonce(iv, packet_number)             → 12-byte nonce
--   aes_128_gcm_encrypt(key, nonce, pt, aad)       → ciphertext_with_tag
--   aes_128_gcm_decrypt(key, nonce, ct_with_tag, aad) → plaintext | nil, err
--   aes_128_ecb_block(key, block)                  → 16-byte block
--
-- @module lib.crypto.backend.ffi_mbedtls

ffi = require "ffi"

-- Opaque struct sizes (safe upper bounds for default build config).
-- Raise GCM_CTX_SIZE to 4608 if MBEDTLS_GCM_LARGE_TABLE is enabled.
GCM_CTX_SIZE = 512
AES_CTX_SIZE = 512

pcall ffi.cdef, [[
  /* Opaque context structs */
  typedef struct { char _opaque[512]; } mbedtls_gcm_context_t;
  typedef struct { char _opaque[512]; } mbedtls_aes_context_t;

  /* GCM */
  void mbedtls_gcm_init   (mbedtls_gcm_context_t *ctx);
  int  mbedtls_gcm_setkey (mbedtls_gcm_context_t *ctx,
                            int cipher_id,
                            const unsigned char *key,
                            unsigned int keybits);
  int  mbedtls_gcm_crypt_and_tag(
                            mbedtls_gcm_context_t *ctx,
                            int mode,
                            size_t length,
                            const unsigned char *iv,   size_t iv_len,
                            const unsigned char *add,  size_t add_len,
                            const unsigned char *input,
                            unsigned char       *output,
                            size_t tag_len,
                            unsigned char       *tag);
  int  mbedtls_gcm_auth_decrypt(
                            mbedtls_gcm_context_t *ctx,
                            size_t length,
                            const unsigned char *iv,   size_t iv_len,
                            const unsigned char *add,  size_t add_len,
                            const unsigned char *tag,  size_t tag_len,
                            const unsigned char *input,
                            unsigned char       *output);
  void mbedtls_gcm_free   (mbedtls_gcm_context_t *ctx);

  /* AES (ECB) */
  void mbedtls_aes_init       (mbedtls_aes_context_t *ctx);
  int  mbedtls_aes_setkey_enc (mbedtls_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits);
  int  mbedtls_aes_crypt_ecb  (mbedtls_aes_context_t *ctx,
                                int mode,
                                const unsigned char input[16],
                                unsigned char       output[16]);
  void mbedtls_aes_free       (mbedtls_aes_context_t *ctx);
]]

-- mbedtls_cipher_id_t: MBEDTLS_CIPHER_ID_AES = 2
-- mbedtls_gcm / mbedtls_aes mode constants
MBEDTLS_CIPHER_ID_AES = 2
MBEDTLS_GCM_ENCRYPT   = 1
MBEDTLS_AES_ENCRYPT   = 1
-- MBEDTLS_ERR_GCM_AUTH_FAILED = -0x0012
MBEDTLS_ERR_GCM_AUTH_FAILED = -18

mbed = ffi.load "mbedcrypto"
{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :validate_quic_iv} = require "ipparse.lib.crypto.backend.common"

--- Constructs a QUIC nonce: XOR last 8 bytes of iv with packet_number (big-endian).
-- @tparam string iv 12-byte IV
-- @tparam number packet_number QUIC packet number
-- @treturn string 12-byte nonce
construct_nonce = (iv, packet_number) ->
  assert #iv == 12, "IV must be 12 bytes (got #{#iv})"
  buf = ffi.new "uint8_t[12]"
  ffi.copy buf, iv, 12
  pn = packet_number
  for i = 11, 4, -1
    buf[i] = ffi.cast "uint8_t", bit.bxor(buf[i], bit.band(pn, 0xFF))
    pn = bit.rshift pn, 8
  ffi.string buf, 12

-- Copy a Lua string into an FFI buffer, always at least 1 byte (avoids
-- passing NULL to mbedTLS for zero-length inputs).
str_to_buf = (s) ->
  n   = #s
  buf = ffi.new "uint8_t[?]", n + 1
  if n > 0 then ffi.copy buf, s, n
  buf, n

--- AES-128-GCM encryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string ciphertext .. 16-byte authentication tag
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  assert #key == 16,   "AES-128-GCM key must be 16 bytes"
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes"

  pt_buf,  pt_len  = str_to_buf plaintext
  aad_buf, aad_len = str_to_buf aad

  ctx = ffi.new "mbedtls_gcm_context_t"
  mbed.mbedtls_gcm_init ctx
  rc = mbed.mbedtls_gcm_setkey ctx, MBEDTLS_CIPHER_ID_AES, key, 128
  assert rc == 0, "mbedtls_gcm_setkey failed (#{rc})"

  out_buf = ffi.new "uint8_t[?]", pt_len + 1
  tag_buf = ffi.new "uint8_t[16]"
  rc = mbed.mbedtls_gcm_crypt_and_tag ctx, MBEDTLS_GCM_ENCRYPT,
    pt_len, nonce, 12,
    aad_buf, aad_len,
    pt_buf, out_buf,
    16, tag_buf
  mbed.mbedtls_gcm_free ctx
  assert rc == 0, "mbedtls_gcm_crypt_and_tag failed (#{rc})"

  (ffi.string out_buf, pt_len) .. (ffi.string tag_buf, 16)

--- AES-128-GCM decryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string ciphertext_with_tag ciphertext concatenated with 16-byte auth tag
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string plaintext on success
-- @treturn nil, string on authentication failure
aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  validate_gcm_key key
  validate_gcm_nonce nonce
  if #ciphertext_with_tag < 16
    return nil, "ciphertext too short (no room for auth tag)"

  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  tag        = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  ct_buf,  ct_len  = str_to_buf ciphertext
  aad_buf, aad_len = str_to_buf aad

  ctx = ffi.new "mbedtls_gcm_context_t"
  mbed.mbedtls_gcm_init ctx
  rc = mbed.mbedtls_gcm_setkey ctx, MBEDTLS_CIPHER_ID_AES, key, 128
  assert rc == 0, "mbedtls_gcm_setkey failed (#{rc})"

  out_buf = ffi.new "uint8_t[?]", ct_len + 1
  tag_buf = ffi.new "uint8_t[16]"
  ffi.copy tag_buf, tag, 16
  rc = mbed.mbedtls_gcm_auth_decrypt ctx,
    ct_len, nonce, 12,
    aad_buf, aad_len,
    tag_buf, 16,
    ct_buf, out_buf
  mbed.mbedtls_gcm_free ctx

  if rc == MBEDTLS_ERR_GCM_AUTH_FAILED
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  if rc != 0
    error "mbedtls_gcm_auth_decrypt failed (#{rc})"

  ffi.string out_buf, ct_len

--- AES-128-ECB single-block encryption (no padding).
-- Used for QUIC header protection mask generation (RFC 9001 §5.4.3).
-- @tparam string key 16-byte AES key
-- @tparam string block exactly 16 bytes of input
-- @treturn string exactly 16 bytes of output
aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  ctx = ffi.new "mbedtls_aes_context_t"
  mbed.mbedtls_aes_init ctx
  rc = mbed.mbedtls_aes_setkey_enc ctx, key, 128
  assert rc == 0, "mbedtls_aes_setkey_enc failed (#{rc})"

  out_buf = ffi.new "uint8_t[16]"
  rc = mbed.mbedtls_aes_crypt_ecb ctx, MBEDTLS_AES_ENCRYPT, block, out_buf
  mbed.mbedtls_aes_free ctx
  assert rc == 0, "mbedtls_aes_crypt_ecb failed (#{rc})"

  ffi.string out_buf, 16

{:construct_nonce, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt, :aes_128_ecb_block}
