--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Common validation and utility functions for crypto backends.
-- This module provides shared patterns used across different crypto backend implementations.
--
-- The `validate_*` helpers guard against programmer errors (keys and nonces are
-- derived internally, never attacker-controlled), so they raise via `assert`.
-- Operational failures (library errors, tag mismatches) are reported by the
-- backends as `nil, err` instead.
--
-- @module lib.crypto.backend.common

{:bxor} = require "ipparse.lib.bit_compat"
:byte, :char = string
unpack or= table.unpack

--- Validates AES-128-GCM key length.
-- @tparam string key The key to validate.
-- @treturn boolean true if valid, error is raised otherwise.
validate_gcm_key = (key) ->
  assert #key == 16, "AES-128-GCM key must be 16 bytes (got #{#key})"
  true

--- Validates AES-128-GCM nonce length.
-- @tparam string nonce The nonce to validate.
-- @treturn boolean true if valid, error is raised otherwise.
validate_gcm_nonce = (nonce) ->
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes (got #{#nonce})"
  true

--- Validates AES-128-ECB key length.
-- @tparam string key The key to validate.
-- @treturn boolean true if valid, error is raised otherwise.
validate_ecb_key = (key) ->
  assert #key == 16, "AES-128-ECB key must be 16 bytes (got #{#key})"
  true

--- Validates AES-128-ECB block length.
-- @tparam string block The block to validate.
-- @treturn boolean true if valid, error is raised otherwise.
validate_ecb_block = (block) ->
  assert #block == 16, "AES-128-ECB block must be 16 bytes (got #{#block})"
  true

--- Validates QUIC IV length.
-- @tparam string iv The IV to validate.
-- @treturn boolean true if valid, error is raised otherwise.
validate_quic_iv = (iv) ->
  assert #iv == 12, "IV must be 12 bytes (got #{#iv})"
  true

--- Constructs a QUIC nonce: XOR the last 8 bytes of the IV with the
-- packet number (big-endian), per RFC 9001 §5.3.
-- Portable implementation shared by all backends (kernel Lua and LuaJIT).
-- @tparam string iv 12-byte IV.
-- @tparam number packet_number QUIC packet number.
-- @treturn string 12-byte nonce.
construct_nonce = (iv, packet_number) ->
  validate_quic_iv iv
  buf = {byte iv, 1, 12}
  pn = packet_number
  for i = 12, 5, -1
    -- Arithmetic (not bit lib) split: packet numbers may exceed 32 bits,
    -- which 32-bit bit libraries would truncate.
    b = pn % 256
    buf[i] = bxor buf[i], b
    pn = (pn - b) / 256
  char unpack buf

--- Splits a ciphertext-with-tag buffer into ciphertext and 16-byte tag.
-- @tparam string ciphertext_with_tag Ciphertext with the auth tag appended.
-- @treturn string|nil The ciphertext, or nil if the input is too short.
-- @treturn string The tag, or an error message when the first value is nil.
split_ct_tag = (ciphertext_with_tag) ->
  return nil, "ciphertext too short (no room for auth tag)" if #ciphertext_with_tag < 16
  ciphertext_with_tag\sub(1, #ciphertext_with_tag - 16), ciphertext_with_tag\sub #ciphertext_with_tag - 15

{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :validate_quic_iv, :construct_nonce, :split_ct_tag}
