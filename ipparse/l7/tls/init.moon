--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TLS Record Parsing and Packing Module
-- This module provides utilities for parsing and packing TLS records.
-- It supports handling different TLS record types, including handshake, alert, and application data.
--
-- ### Features
-- - Parse and pack TLS records.
-- - Support for various TLS record types.
--
-- ### TLS Record Structure
-- ```
-- TLS Record {
--   type (8): Record type (e.g., handshake, alert, application data).
--   ver (8): Major version of the protocol.
--   subver (8): Minor version of the protocol.
--   len (16): Length of the record payload.
--   payload (variable): Record payload (e.g., handshake message).
-- }
-- ```
--
-- References:
-- - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
--
-- @module tls

pack: sp, unpack: su = string
:bidirectional = require"ipparse.fun"

--- Packs a TLS record into a binary string.
-- Constructs the binary representation of the TLS record.
-- @tparam table self The TLS record object.
-- @treturn string Binary string representing the packed TLS record.
pack = =>
  sp ">B BB H", @type, @ver, @subver, @len

_mt =
  --- Converts the TLS record object to a binary string.
  -- @treturn string Binary string representing the TLS record.
  __tostring: pack

--- Parses a binary string into a TLS record structure.
-- Extracts the record type, version, and length from the binary string.
-- @tparam string self The binary string containing the TLS record.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed TLS record as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  _type, ver, subver, len, _off = su ">B BB H", @, off
  setmetatable({
    type: _type, data_off: _off
    :ver, :subver, :len
  }, _mt), _off

--- TLS Record Types
-- Provides a mapping of TLS record type codes to their names.
record_types = bidirectional {
  [0x14]: "change_cipher_spec"
  [0x15]: "alert"
  [0x16]: "handshake"
  [0x17]: "application_data"
  [0x18]: "heartbeat"
}

:parse, :pack, :record_types
