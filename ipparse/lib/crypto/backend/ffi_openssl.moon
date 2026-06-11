--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- LuaJIT FFI crypto backend for ipparse.
--
-- Implements the ipparse crypto interface using LuaJIT FFI and OpenSSL libcrypto.
-- Requires LuaJIT 2.x and libcrypto.so (OpenSSL 1.1+ or 3.x).
--
-- Implements:
--   aes_128_gcm_encrypt(key, nonce, plaintext, aad) → ciphertext_with_tag
--   aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad) → plaintext | nil, err
--   aes_128_ecb_block(key, block) → encrypted_block
--
-- @module lib.crypto.backend.ffi_openssl

ffi = require "ffi"

ffi.cdef [[
  /* EVP generic */
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
  int             EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

  const EVP_CIPHER *EVP_aes_128_gcm(void);
  const EVP_CIPHER *EVP_aes_128_ecb(void);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
]]

-- EVP_CIPHER_CTX_ctrl constants
EVP_CTRL_GCM_SET_IVLEN  = 0x9
EVP_CTRL_GCM_GET_TAG    = 0x10
EVP_CTRL_GCM_SET_TAG    = 0x11

ssl = ffi.load "crypto"
{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :construct_nonce, :split_ct_tag} = require "ipparse.lib.crypto.backend.common"

-- Free the cipher context and report an operational failure as `nil, err`.
fail = (ctx, msg) ->
  ssl.EVP_CIPHER_CTX_free ctx if ctx != nil
  nil, msg

--- AES-128-GCM encryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string|nil ciphertext .. 16-byte authentication tag, or nil on failure
-- @treturn string|nil error message when the first value is nil
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  validate_gcm_key key
  validate_gcm_nonce nonce

  ctx = ssl.EVP_CIPHER_CTX_new!
  return fail nil, "EVP_CIPHER_CTX_new failed" if ctx == nil

  return fail ctx, "EVP_EncryptInit_ex (cipher) failed" unless 1 == ssl.EVP_EncryptInit_ex ctx, ssl.EVP_aes_128_gcm!, nil, nil, nil
  return fail ctx, "EVP_CTRL_GCM_SET_IVLEN failed" unless 1 == ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil
  return fail ctx, "EVP_EncryptInit_ex (key/nonce) failed" unless 1 == ssl.EVP_EncryptInit_ex ctx, nil, nil, key, nonce

  outl = ffi.new "int[1]"

  -- Feed AAD
  if #aad > 0
    return fail ctx, "EVP_EncryptUpdate (AAD) failed" unless 1 == ssl.EVP_EncryptUpdate ctx, nil, outl, aad, #aad

  -- Encrypt plaintext
  ciphertext_buf = ffi.new "uint8_t[?]", #plaintext + 16
  return fail ctx, "EVP_EncryptUpdate (plaintext) failed" unless 1 == ssl.EVP_EncryptUpdate ctx, ciphertext_buf, outl, plaintext, #plaintext
  ciphertext_len = outl[0]

  final_buf = ffi.new "uint8_t[16]"
  return fail ctx, "EVP_EncryptFinal_ex failed" unless 1 == ssl.EVP_EncryptFinal_ex ctx, final_buf, outl
  ciphertext_len += outl[0]

  -- Retrieve auth tag
  tag_buf = ffi.new "uint8_t[16]"
  return fail ctx, "EVP_CTRL_GCM_GET_TAG failed" unless 1 == ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf

  ssl.EVP_CIPHER_CTX_free ctx

  (ffi.string ciphertext_buf, ciphertext_len) .. (ffi.string tag_buf, 16)

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
  ciphertext, tag = split_ct_tag ciphertext_with_tag
  return nil, tag unless ciphertext

  ctx = ssl.EVP_CIPHER_CTX_new!
  return fail nil, "EVP_CIPHER_CTX_new failed" if ctx == nil

  return fail ctx, "EVP_DecryptInit_ex (cipher) failed" unless 1 == ssl.EVP_DecryptInit_ex ctx, ssl.EVP_aes_128_gcm!, nil, nil, nil
  return fail ctx, "EVP_CTRL_GCM_SET_IVLEN failed" unless 1 == ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil
  return fail ctx, "EVP_DecryptInit_ex (key/nonce) failed" unless 1 == ssl.EVP_DecryptInit_ex ctx, nil, nil, key, nonce

  outl = ffi.new "int[1]"

  -- Feed AAD
  if #aad > 0
    return fail ctx, "EVP_DecryptUpdate (AAD) failed" unless 1 == ssl.EVP_DecryptUpdate ctx, nil, outl, aad, #aad

  -- Decrypt ciphertext
  plaintext_buf = ffi.new "uint8_t[?]", #ciphertext + 16
  return fail ctx, "EVP_DecryptUpdate (ciphertext) failed" unless 1 == ssl.EVP_DecryptUpdate ctx, plaintext_buf, outl, ciphertext, #ciphertext
  plaintext_len = outl[0]

  -- Set expected tag
  tag_buf = ffi.new "uint8_t[16]"
  ffi.copy tag_buf, tag, 16
  return fail ctx, "EVP_CTRL_GCM_SET_TAG failed" unless 1 == ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf

  -- Finalise (verifies tag)
  final_buf = ffi.new "uint8_t[16]"
  rc = ssl.EVP_DecryptFinal_ex ctx, final_buf, outl
  ssl.EVP_CIPHER_CTX_free ctx

  if rc != 1
    return nil, "AES-128-GCM authentication failed (tag mismatch)"

  plaintext_len += outl[0]
  ffi.string plaintext_buf, plaintext_len

--- AES-128-ECB single-block encryption (no padding).
-- Used for QUIC header protection mask generation (RFC 9001 §5.4.3).
-- @tparam string key 16-byte AES key
-- @tparam string block exactly 16 bytes of input
-- @treturn string|nil exactly 16 bytes of output, or nil on failure
-- @treturn string|nil error message when the first value is nil
aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  ctx = ssl.EVP_CIPHER_CTX_new!
  return fail nil, "EVP_CIPHER_CTX_new failed" if ctx == nil

  return fail ctx, "EVP_EncryptInit_ex (ECB) failed" unless 1 == ssl.EVP_EncryptInit_ex ctx, ssl.EVP_aes_128_ecb!, nil, key, nil

  -- Disable padding so we get exactly 16 bytes back
  ffi.cdef "int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);" if not pcall -> ffi.C.EVP_CIPHER_CTX_set_padding
  ssl.EVP_CIPHER_CTX_set_padding ctx, 0

  outl = ffi.new "int[1]"
  out_buf = ffi.new "uint8_t[32]"

  return fail ctx, "EVP_EncryptUpdate (ECB) failed" unless 1 == ssl.EVP_EncryptUpdate ctx, out_buf, outl, block, 16
  len = outl[0]

  final_buf = ffi.new "uint8_t[16]"
  return fail ctx, "EVP_EncryptFinal_ex (ECB) failed" unless 1 == ssl.EVP_EncryptFinal_ex ctx, final_buf, outl
  len += outl[0]

  ssl.EVP_CIPHER_CTX_free ctx
  return nil, "AES-128-ECB output length mismatch: expected 16, got #{len}" if len != 16
  ffi.string out_buf, 16

{:construct_nonce, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt, :aes_128_ecb_block}
