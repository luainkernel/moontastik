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
{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :validate_quic_iv} = require "ipparse.lib.crypto.backend.common"

--- Constructs a QUIC nonce: XOR last 8 bytes of iv with packet_number (big-endian 8 bytes).
-- Exported so callers can construct nonces without duplicating logic.
-- @tparam string iv 12-byte IV
-- @tparam number packet_number QUIC packet number
-- @treturn string 12-byte nonce
construct_nonce = (iv, packet_number) ->
  validate_quic_iv iv
  buf = ffi.new "uint8_t[12]"
  ffi.copy buf, iv, 12
  -- XOR bytes 4..11 (0-indexed) with big-endian packet_number
  pn = packet_number
  for i = 11, 4, -1
    buf[i] = ffi.cast "uint8_t", bit.bxor(buf[i], bit.band(pn, 0xFF))
    pn = bit.rshift pn, 8
  ffi.string buf, 12

--- AES-128-GCM encryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string ciphertext .. 16-byte authentication tag
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  validate_gcm_key key
  validate_gcm_nonce nonce

  ctx = ssl.EVP_CIPHER_CTX_new!
  assert ctx != nil, "EVP_CIPHER_CTX_new failed"

  ok = ssl.EVP_EncryptInit_ex ctx, ssl.EVP_aes_128_gcm!, nil, nil, nil
  assert ok == 1, "EVP_EncryptInit_ex (cipher) failed"

  ok = ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil
  assert ok == 1, "EVP_CTRL_GCM_SET_IVLEN failed"

  ok = ssl.EVP_EncryptInit_ex ctx, nil, nil, key, nonce
  assert ok == 1, "EVP_EncryptInit_ex (key/nonce) failed"

  outl = ffi.new "int[1]"

  -- Feed AAD
  if #aad > 0
    ok = ssl.EVP_EncryptUpdate ctx, nil, outl, aad, #aad
    assert ok == 1, "EVP_EncryptUpdate (AAD) failed"

  -- Encrypt plaintext
  ciphertext_buf = ffi.new "uint8_t[?]", #plaintext + 16
  ok = ssl.EVP_EncryptUpdate ctx, ciphertext_buf, outl, plaintext, #plaintext
  assert ok == 1, "EVP_EncryptUpdate (plaintext) failed"
  ciphertext_len = outl[0]

  final_buf = ffi.new "uint8_t[16]"
  ok = ssl.EVP_EncryptFinal_ex ctx, final_buf, outl
  assert ok == 1, "EVP_EncryptFinal_ex failed"
  ciphertext_len += outl[0]

  -- Retrieve auth tag
  tag_buf = ffi.new "uint8_t[16]"
  ok = ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf
  assert ok == 1, "EVP_CTRL_GCM_GET_TAG failed"

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
  if #ciphertext_with_tag < 16
    return nil, "ciphertext too short (no room for auth tag)"

  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  tag        = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  ctx = ssl.EVP_CIPHER_CTX_new!
  assert ctx != nil, "EVP_CIPHER_CTX_new failed"

  ok = ssl.EVP_DecryptInit_ex ctx, ssl.EVP_aes_128_gcm!, nil, nil, nil
  assert ok == 1, "EVP_DecryptInit_ex (cipher) failed"

  ok = ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil
  assert ok == 1, "EVP_CTRL_GCM_SET_IVLEN failed"

  ok = ssl.EVP_DecryptInit_ex ctx, nil, nil, key, nonce
  assert ok == 1, "EVP_DecryptInit_ex (key/nonce) failed"

  outl = ffi.new "int[1]"

  -- Feed AAD
  if #aad > 0
    ok = ssl.EVP_DecryptUpdate ctx, nil, outl, aad, #aad
    assert ok == 1, "EVP_DecryptUpdate (AAD) failed"

  -- Decrypt ciphertext
  plaintext_buf = ffi.new "uint8_t[?]", #ciphertext + 16
  ok = ssl.EVP_DecryptUpdate ctx, plaintext_buf, outl, ciphertext, #ciphertext
  assert ok == 1, "EVP_DecryptUpdate (ciphertext) failed"
  plaintext_len = outl[0]

  -- Set expected tag
  tag_buf = ffi.new "uint8_t[16]"
  ffi.copy tag_buf, tag, 16
  ok = ssl.EVP_CIPHER_CTX_ctrl ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf
  assert ok == 1, "EVP_CTRL_GCM_SET_TAG failed"

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
-- @treturn string exactly 16 bytes of output
aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  ctx = ssl.EVP_CIPHER_CTX_new!
  assert ctx != nil, "EVP_CIPHER_CTX_new failed"

  ok = ssl.EVP_EncryptInit_ex ctx, ssl.EVP_aes_128_ecb!, nil, key, nil
  assert ok == 1, "EVP_EncryptInit_ex (ECB) failed"

  -- Disable padding so we get exactly 16 bytes back
  ffi.cdef "int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);" if not pcall -> ffi.C.EVP_CIPHER_CTX_set_padding
  ssl.EVP_CIPHER_CTX_set_padding ctx, 0

  outl = ffi.new "int[1]"
  out_buf = ffi.new "uint8_t[32]"

  ok = ssl.EVP_EncryptUpdate ctx, out_buf, outl, block, 16
  assert ok == 1, "EVP_EncryptUpdate (ECB) failed"
  len = outl[0]

  final_buf = ffi.new "uint8_t[16]"
  ok = ssl.EVP_EncryptFinal_ex ctx, final_buf, outl
  assert ok == 1, "EVP_EncryptFinal_ex (ECB) failed"
  len += outl[0]

  ssl.EVP_CIPHER_CTX_free ctx
  assert len == 16, "AES-128-ECB output length mismatch: expected 16, got #{len}"
  ffi.string out_buf, 16

{:construct_nonce, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt, :aes_128_ecb_block}
