--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Common validation and utility functions for crypto backends.
-- This module provides shared patterns used across different crypto backend implementations.
--
-- @module lib.crypto.backend.common

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

{:validate_gcm_key, :validate_gcm_nonce, :validate_ecb_key, :validate_ecb_block, :validate_quic_iv}
