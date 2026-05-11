--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- LuaJIT FFI crypto backend for ipparse — wolfSSL.
--
-- Implements the ipparse crypto interface using LuaJIT FFI and libwolfssl.
-- Requires LuaJIT 2.x and libwolfssl.so.
--
-- AES-128-GCM uses the wolfSSL native wc_AesGcm* API.
--   wc_AesInit is intentionally NOT called: it registers the struct in wolfSSL's
--   global object-tracking list, whose atexit cleanup segfaults with
--   LuaJIT-heap-allocated structs.  wc_AesGcmSetKey works on a zero-initialised
--   struct so the init call is not needed.
-- AES-128-ECB uses direct wolfCrypt APIs (wc_AesSetKey + wc_AesEncryptDirect).
--
-- Implements:
--   aes_128_gcm_encrypt(key, nonce, plaintext, aad) → ciphertext_with_tag
--   aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad) → plaintext | nil, err
--   aes_128_ecb_block(key, block) → encrypted_block
--
-- @module lib.crypto.backend.ffi_wolfssl

ffi = require "ffi"
{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :validate_quic_iv} = require "ipparse.lib.crypto.backend.common"

-- Native GCM API — opaque Aes struct.
-- Some distro builds enable larger WC_Aes layouts (AES-NI/ARM accel paths),
-- so keep a generous buffer to avoid overruns when wolfSSL writes internals.
pcall ffi.cdef, [[
  typedef struct { char _opaque[4096]; } WC_Aes;

  int wc_AesGcmSetKey (WC_Aes *aes, const unsigned char *key, unsigned int keySz);
  int wc_AesGcmEncrypt(WC_Aes *aes,
                       unsigned char *out, const unsigned char *in, unsigned int sz,
                       const unsigned char *iv, unsigned int ivSz,
                       unsigned char *authTag, unsigned int authTagSz,
                       const unsigned char *authIn, unsigned int authInSz);
  int wc_AesGcmDecrypt(WC_Aes *aes,
                       unsigned char *out, const unsigned char *in, unsigned int sz,
                       const unsigned char *iv, unsigned int ivSz,
                       const unsigned char *authTag, unsigned int authTagSz,
                       const unsigned char *authIn, unsigned int authInSz);
]]

pcall ffi.cdef, [[
  int wc_AesSetKey(WC_Aes *aes, const unsigned char *key, unsigned int keySz,
                   const unsigned char *iv, int dir);
  int wc_AesEncryptDirect(WC_Aes *aes, unsigned char *out, const unsigned char *in);
]]

load_wolfssl = ->
  candidates = {
    "wolfssl"
    "libwolfssl"
    "libwolfssl.so"
  }
  seen = {}
  for name in *candidates
    seen[name] = true

  -- Discover concrete sonames dynamically when available (e.g. libwolfssl.so.5.8.4.x)
  if io and io.popen
    for dir in *{"/usr/lib", "/lib", "/usr/local/lib"}
      cmd = "ls -1 #{dir}/libwolfssl.so* 2>/dev/null"
      p = io.popen cmd
      if p
        for line in p\lines!
          if line and #line > 0 and not seen[line]
            candidates[#candidates + 1] = line
            seen[line] = true
        p\close!

  last_err = nil
  for name in *candidates
    ok, lib = pcall ffi.load, name
    return lib if ok and lib
    last_err = lib
  error "ffi_wolfssl: cannot load wolfssl library (tried #{table.concat candidates, ', '}): #{last_err}"

wssl = load_wolfssl!

direct_ecb_available = (pcall -> wssl.wc_AesSetKey) and (pcall -> wssl.wc_AesEncryptDirect)
unless direct_ecb_available
  error "ffi_wolfssl: no AES-128-ECB implementation available (missing wc_AesSetKey/wc_AesEncryptDirect)"

--- Constructs a QUIC nonce: XOR last 8 bytes of iv with packet_number (big-endian).
-- @tparam string iv 12-byte IV
-- @tparam number packet_number QUIC packet number
-- @treturn string 12-byte nonce
construct_nonce = (iv, packet_number) ->
  validate_quic_iv iv
  buf = ffi.new "uint8_t[12]"
  ffi.copy buf, iv, 12
  pn = packet_number
  for i = 11, 4, -1
    buf[i] = ffi.cast "uint8_t", bit.bxor(buf[i], bit.band(pn, 0xFF))
    pn = bit.rshift pn, 8
  ffi.string buf, 12

-- Copy a Lua string into a padded FFI buffer.
-- wolfSSL's AES-NI path may read up to 32 bytes beyond the declared length
-- (look-ahead reads for multi-block SIMD operations).  We always over-allocate
-- by at least 32 bytes so those reads land in zeroed memory, not unmapped pages.
str_to_buf = (s) ->
  n   = #s
  buf = ffi.new "uint8_t[?]", n + 32   -- 32-byte safety margin
  if n > 0 then ffi.copy buf, s, n
  buf, n

--- AES-128-GCM encryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string ciphertext .. 16-byte authentication tag
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  assert #key == 16,   "AES-128-GCM key must be 16 bytes (got #{#key})"
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes (got #{#nonce})"

  pt_buf, pt_len   = str_to_buf plaintext
  aad_buf, aad_len = str_to_buf aad

  aes = ffi.new "WC_Aes"
  rc = wssl.wc_AesGcmSetKey aes, key, 16
  assert rc == 0, "wc_AesGcmSetKey failed (#{rc})"

  out_buf = ffi.new "uint8_t[?]", pt_len + 16
  tag_buf = ffi.new "uint8_t[16]"
  rc = wssl.wc_AesGcmEncrypt aes,
    out_buf, pt_buf, pt_len,
    nonce, 12,
    tag_buf, 16,
    aad_buf, aad_len
  assert rc == 0, "wc_AesGcmEncrypt failed (#{rc})"

  (ffi.string out_buf, pt_len) .. (ffi.string tag_buf, 16)

--- AES-128-GCM decryption.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string ciphertext_with_tag ciphertext concatenated with 16-byte auth tag
-- @tparam string aad additional authenticated data (may be "")
-- @treturn string plaintext on success
-- @treturn nil, string on authentication failure
aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  assert #key == 16,   "AES-128-GCM key must be 16 bytes"
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes"
  if #ciphertext_with_tag < 16
    return nil, "ciphertext too short (no room for auth tag)"

  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  tag        = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  ct_buf, ct_len   = str_to_buf ciphertext
  aad_buf, aad_len = str_to_buf aad

  aes = ffi.new "WC_Aes"
  rc = wssl.wc_AesGcmSetKey aes, key, 16
  assert rc == 0, "wc_AesGcmSetKey failed (#{rc})"

  out_buf = ffi.new "uint8_t[?]", ct_len + 1
  tag_buf = ffi.new "uint8_t[16]"
  ffi.copy tag_buf, tag, 16
  rc = wssl.wc_AesGcmDecrypt aes,
    out_buf, ct_buf, ct_len,
    nonce, 12,
    tag_buf, 16,
    aad_buf, aad_len

  if rc != 0
    return nil, "AES-128-GCM authentication failed (tag mismatch)"

  ffi.string out_buf, ct_len

--- AES-128-ECB single-block encryption (no padding).
-- Used for QUIC header protection mask generation (RFC 9001 §5.4.3).
-- Uses wolfSSL direct AES API.
-- @tparam string key 16-byte AES key
-- @tparam string block exactly 16 bytes of input
-- @treturn string exactly 16 bytes of output
aes_128_ecb_block = (key, block) ->
  validate_ecb_key key
  validate_ecb_block block

  out_buf = ffi.new "uint8_t[16]"
  aes = ffi.new "WC_Aes"
  -- wolfSSL convention: 0 = encrypt mode
  rc = wssl.wc_AesSetKey aes, key, 16, nil, 0
  assert rc == 0, "wc_AesSetKey failed (#{rc})"
  rc = wssl.wc_AesEncryptDirect aes, out_buf, block
  assert rc == 0, "wc_AesEncryptDirect failed (#{rc})"

  ffi.string out_buf, 16

{:construct_nonce, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt, :aes_128_ecb_block}
