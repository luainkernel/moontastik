--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TLS Handshake Extension Parsing and Packing Module
-- This module provides utilities for parsing and packing TLS handshake extensions.
-- It supports handling extension types and their associated data.
--
-- ### Features
-- - Parse and pack TLS handshake extensions.
-- - Support for extension type and data fields.
--
-- ### TLS Handshake Extension Structure
-- ```
-- Extension {
--   type (16): Extension type.
--   data (variable): Extension data, prefixed by its length as uint16.
-- }
-- ```
--
-- References:
-- - RFC 6066: Transport Layer Security (TLS) Extensions
--
-- @module tls.handshake.extension

pack: sp, unpack: su = string

--- Packs a TLS handshake extension into a binary string.
-- Constructs the binary representation of the extension.
-- @tparam table self The extension object.
-- @treturn string Binary string representing the packed extension.
pack = =>
  sp ">H s2", @type, @data

_mt =
  --- Converts the extension object to a binary string.
  -- @treturn string Binary string representing the extension.
  __tostring: pack

--- Parses a binary string into a TLS handshake extension structure.
-- Extracts the extension type and data from the binary string.
-- @tparam string self The binary string containing the extension.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed extension as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  _type, data, _off = su ">H s2", @, off
  setmetatable({type: _type, :data}, _mt), _off

:parse, :pack
