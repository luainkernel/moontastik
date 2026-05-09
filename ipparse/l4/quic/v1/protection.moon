--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC v1 header and packet protection (RFC 9001).
--
-- **Backend-agnostic**: all cryptographic operations are delegated to a
-- crypto backend table passed as the last argument (or returned by
-- `require "ipparse.lib.crypto.backend.ffi_openssl"`).
-- The backend must expose:
--   `aes_128_ecb_block(key, block)` → 16 bytes
--   `aes_128_gcm_encrypt(key, nonce, plaintext, aad)` → ciphertext_with_tag
--   `aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)` → plaintext | nil, err
--
-- ### Header protection (RFC 9001 §5.4)
-- mask = AES-ECB(hp_key, sample)    -- sample = 16 bytes from encrypted payload
-- Long header:  first_byte ^= mask[0] & 0x0F ; pn_bytes ^= mask[1..pn_len]
-- Short header: first_byte ^= mask[0] & 0x1F ; pn_bytes ^= mask[1..pn_len]
--
-- ### Packet number nonce (RFC 9001 §5.3)
-- nonce = iv XOR (pn padded to 12 bytes, big-endian)
--
-- @module l4.quic.v1.protection

{:band, :bor, :bxor, :rshift} = require "ipparse.lib.bit_compat"
pack: sp, unpack: su = require "ipparse.lib.pack_compat"
byte = string.byte
tunpack = table.unpack or unpack

--- Constructs the QUIC nonce by XOR-ing the IV with the packet number.
-- @tparam string iv 12-byte string
-- @tparam number pn packet number (non-negative integer)
-- @treturn string 12-byte nonce
construct_nonce = (iv, pn) ->
  -- Build big-endian 12-byte representation of pn
  buf = {byte iv, 1, 12}
  -- XOR the last 8 bytes (indices 5..12, 1-based) with pn
  for i = 12, 5, -1
    buf[i] = bxor buf[i], band(pn, 0xFF)
    pn = rshift pn, 8
  string.char tunpack buf

--- Extracts the 16-byte sample for header protection from encrypted payload.
-- RFC 9001 §5.4.2: sample starts at offset 4 past the start of the encrypted payload.
-- @tparam string pkt    full packet bytes (binary string)
-- @tparam number enc_off 1-based offset where encrypted payload starts (after pn field)
-- @treturn string 16-byte sample
sample_from_packet = (pkt, enc_off) ->
  s = enc_off + 4
  assert s + 15 <= #pkt, "packet too short to extract header protection sample"
  pkt\sub s, s + 15

--- Applies (or removes — same operation) header protection.
-- Works in-place on the mutable bytes table `hdr_bytes`.
-- @tparam table  hdr_bytes  array of byte values (1-based), modified in place
-- @tparam number first_byte_idx  1-based index of protected first byte in hdr_bytes
-- @tparam number pn_off     1-based index in hdr_bytes where the packet number starts
-- @tparam number pn_len     number of packet number bytes (1..4)
-- @tparam string mask       5-byte mask from AES-ECB
-- @tparam boolean long      true for long header, false for short
apply_header_mask = (hdr_bytes, first_byte_idx, pn_off, pn_len, mask, long) ->
  m0 = byte mask, 1
  fb_mask = long and 0x0F or 0x1F
  hdr_bytes[first_byte_idx] = bxor hdr_bytes[first_byte_idx], band(m0, fb_mask)
  for i = 1, pn_len
    hdr_bytes[pn_off + i - 1] = bxor hdr_bytes[pn_off + i - 1], byte(mask, i + 1)

recover_packet_number = nil

unprotect_header = (pkt, pn_off, hp_key, long, expected_pn, crypto) ->
  sample = sample_from_packet pkt, pn_off
  mask = crypto.aes_128_ecb_block hp_key, sample
  m0 = byte mask, 1
  fb_mask = long and 0x0F or 0x1F
  first = bxor byte(pkt, 1), band(m0, fb_mask)
  pn_len = band(first, 0x03) + 1

  truncated_pn = 0
  pn_chars = {}
  for i = 1, pn_len
    b = bxor byte(pkt, pn_off + i - 1), byte(mask, i + 1)
    truncated_pn = truncated_pn * 256 + b
    pn_chars[i] = string.char b

  full_pn = recover_packet_number truncated_pn, expected_pn, pn_len
  aad = string.char(first) ..
        (pn_off > 2 and pkt\sub(2, pn_off - 1) or "") ..
        table.concat(pn_chars)
  aad, full_pn, pn_len

--- Decodes a big-endian packet number from `n` bytes.
pn_from_bytes = (hdr_bytes, pn_off, pn_len) ->
  pn = 0
  for i = 0, pn_len - 1
    pn = pn * 256 + hdr_bytes[pn_off + i]
  pn

--- Recovers the full packet number from a truncated one (RFC 9000 §A.3).
-- @tparam number truncated  the pn_len-byte truncated packet number
-- @tparam number expected   the expected next packet number (largest acknowledged + 1)
-- @tparam number pn_len     number of bytes used in the wire encoding
-- @treturn number full packet number
recover_packet_number = (truncated, expected, pn_len) ->
  pn_win = 1
  for _ = 1, pn_len * 8
    pn_win *= 2
  pn_hwin = rshift pn_win, 1
  candidate = (expected - (expected % pn_win)) + truncated
  if candidate <= expected - pn_hwin
    candidate + pn_win
  elseif candidate > expected + pn_hwin and candidate >= pn_win
    candidate - pn_win
  else
    candidate

--- Removes header protection from a raw QUIC Initial (long-header) packet.
--
-- Returns an immutable view: the function returns modified bytes, not a new string.
-- Caller should reconstruct the header string only if needed.
--
-- @tparam string  pkt          raw QUIC packet bytes (binary string, 1-based)
-- @tparam number  pn_off       1-based offset of the (protected) packet number field
--                              in the packet (computed during header parsing)
-- @tparam string  hp_key       16-byte header protection key
-- @tparam boolean long         true for long header, false for short
-- @tparam number  expected_pn  expected next packet number (for full PN recovery)
-- @tparam table   crypto       backend table (must have `aes_128_ecb_block`)
-- @treturn table  hdr_bytes    modified byte array of the entire packet
-- @treturn number pn           recovered full packet number
-- @treturn number pn_len       packet number length in bytes (1..4)
remove_header_protection = (pkt, pn_off, hp_key, long, expected_pn, crypto) ->
  aad, full_pn, pn_len = unprotect_header pkt, pn_off, hp_key, long, expected_pn, crypto
  hdr_bytes = {}
  for i = 1, #aad
    hdr_bytes[i] = byte aad, i
  hdr_bytes, full_pn, pn_len

--- Decrypts a QUIC packet payload (AEAD, RFC 9001 §5.3).
--
-- @tparam string pkt          raw QUIC packet bytes
-- @tparam number payload_off  1-based offset of the encrypted payload (after pn field)
-- @tparam string key          16-byte packet protection key
-- @tparam string iv           12-byte packet protection IV
-- @tparam number pn           full recovered packet number (used to build nonce)
-- @tparam string aad          additional authenticated data (unprotected header bytes)
-- @tparam table  crypto       backend table (must have `aes_128_gcm_decrypt`)
-- @treturn string             decrypted plaintext (frames)
-- @treturn nil, string        on authentication failure
decrypt_payload = (pkt, payload_off, key, iv, pn, aad, crypto) ->
  nonce = construct_nonce iv, pn
  ciphertext_with_tag = pkt\sub payload_off
  crypto.aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, aad

--- Encrypts a QUIC packet payload (AEAD, RFC 9001 §5.3).
-- @tparam string plaintext    frame data
-- @tparam string key          16-byte packet protection key
-- @tparam string iv           12-byte packet protection IV
-- @tparam number pn           packet number
-- @tparam string aad          unprotected header (additional authenticated data)
-- @tparam table  crypto       backend table
-- @treturn string ciphertext_with_tag
encrypt_payload = (plaintext, key, iv, pn, aad, crypto) ->
  nonce = construct_nonce iv, pn
  crypto.aes_128_gcm_encrypt key, nonce, plaintext, aad

{
  :construct_nonce
  :sample_from_packet
  :unprotect_header
  :remove_header_protection
  :recover_packet_number
  :decrypt_payload
  :encrypt_payload
}
