--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Version 1 Module
-- This module provides constants, utilities, and metatables specific to QUIC version 1.
-- It includes definitions for packet types, header byte masks, and the initial salt used for key derivation.
-- Additionally, it provides functions to generate metatables for manipulating QUIC header fields.
--
-- ### Features
-- - Constants for QUIC version 1, including `version` and `initial_salt`.
-- - Definitions for long and short header byte masks.
-- - Bidirectional mappings for packet types and header fields.
-- - Utilities for generating metatables for QUIC header manipulation.
--
-- ### QUIC-v1 Packet Structure
-- ```
-- Long Header {
--   byte1 (8): First byte containing flags and header form.
--   version (32): QUIC version (always 0x01 for QUIC-v1).
--   dst_connection_id (variable): Destination Connection ID.
--   src_connection_id (variable): Source Connection ID.
--   payload (variable): Packet payload (e.g., frames).
-- }
--
-- Short Header {
--   byte1 (8): First byte containing flags and header form.
--   dst_connection_id (variable): Destination Connection ID.
--   payload (variable): Packet payload (e.g., frames).
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module quic.v1

:upper = string
:bidirectional, :zero_indexed = require"ipparse.fun"

--- QUIC version number as found in the long-header version field (0x01 for version 1).
version = 0x01

--- Initial salt used for key derivation in QUIC version 1, as a hexadecimal string.
initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

--- Masks for the first byte of a long QUIC header.
-- Provides bidirectional mappings for header fields such as `HEADER_FORM`, `FIXED_BIT`, and `PKT_TYPE`.
byte1_long = bidirectional {
  HEADER_FORM:  0x80
  FIXED_BIT:    0x40
  PKT_TYPE:     0x30
  TYPE_BITS:    0x0f
}

--- Masks for the first byte of a short QUIC header.
-- Provides bidirectional mappings for header fields such as `HEADER_FORM`, `FIXED_BIT`, and `KEY_PHASE`.
byte1_short = bidirectional {
  HEADER_FORM:    0x80
  FIXED_BIT:      0x40
  SPIN_BIT:       0x20
  RESERVED_BITS:  0x18
  KEY_PHASE:      0x04
  PKT_NUM_LENGTH: 0x03
}

--- Packet types for QUIC version 1.
-- Provides bidirectional mappings for packet types such as `initial`, `zero_rtt`, `handshake`, and `retry`.
packet_types = zero_indexed {"initial", "zero_rtt", "handshake", "retry"}
packet_types[i << 4] = packet_types[i] for i = 0, #packet_types-1
packet_types = bidirectional packet_types

--- Generates a metatable for manipulating QUIC header fields.
-- The generated metatable allows for reading and writing header fields using string keys.
-- @tparam table byte1 A table containing bidirectional mappings for header fields.
-- @treturn table The generated metatable.
generate_mt = (byte1) -> {
  --- Reads a header field value.
  -- @tparam string k The name of the header field (e.g., `HEADER_FORM`).
  -- @treturn number The value of the header field.
  __index: (k) =>
    if type(k) == "string"
      if mask = byte1[upper k]
        @byte1 & mask

  --- Writes a value to a header field.
  -- @tparam string k The name of the header field (e.g., `HEADER_FORM`).
  -- @tparam boolean|number v The value to set (`true` to set the field, `false` or `nil` to clear it).
  __newindex: (k, v) =>
    if type(k) == "string"
      if mask = byte1[upper k]
        v = mask if v == true
        @byte1 = (@byte1 & ~mask) | (v or 0)
}

{
  :version, :initial_salt
  long_mt: generate_mt(byte1_long)
  short_mt: generate_mt(byte1_short)
  :byte1_long, :byte1_short, :packet_types
}
