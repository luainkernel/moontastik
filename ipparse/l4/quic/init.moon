--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating QUIC headers.
-- It supports both long and short headers, automatically determining the type and delegating to the appropriate functions.
-- Additionally, it includes utilities for handling QUIC versions, connection IDs, and flags.
--
-- ### Features
-- - Parse and pack QUIC headers (long and short).
-- - Handle QUIC versions and connection IDs.
-- - Manage QUIC-specific flags.
--
-- ### QUIC Header Structure
-- ```
-- QUIC Header {
--   byte1 (8): First byte containing flags and header form.
--   version (32): QUIC version (for long headers).
--   dst_connection_id (variable): Destination Connection ID.
--   src_connection_id (variable): Source Connection ID (for long headers).
--   payload (variable): Payload data.
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 8999: Version-Independent Properties of QUIC
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module quic

pack: sp, unpack: su, :byte = string
:bidirectional = require"ipparse.fun"

versions = {v.version, v for v in *[require"ipparse.l4.quic.#{v}" for v in *{"version_negotiation", "v1"}]}

flags = bidirectional {
  HEADER_FORM: 0x80
}
:HEADER_FORM = flags

--- Packs the QUIC header and payload into a binary string.
-- Constructs the binary representation of the QUIC header based on whether it is a long or short header.
-- @tparam table self The QUIC header object.
-- @treturn string Binary string representing the packed QUIC header and payload.
pack = =>
  if @long_header
    sp(">BH s1 s1", @byte1, @version, @dst_connection_id, @src_connection_id)..(@data and "#{@data}" or "")
  else
    sp(">B", @byte1) .. @dst_connection_id

_mt =
  --- Converts the QUIC header object to a binary string.
  -- @tparam table self The QUIC header object.
  -- @treturn string Binary string representing the QUIC header and payload.
  __tostring: pack

for {:long_mt, :short_mt} in *versions
  long_mt[k] or= v for k, v in pairs _mt
  short_mt[k] or= v for k, v in pairs _mt

--- Parses a long QUIC header from a binary string.
-- Extracts the version, destination connection ID, and source connection ID.
-- @tparam string self The binary string containing the QUIC header.
-- @tparam number off Offset to start parsing from.
-- @tparam number byte1 The first byte of the header.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse_long_header = (off, byte1) =>
  version, dst_connection_id, src_connection_id, _off = su ">I4 s1 s1", @, off
  local mt
  if v = versions[version]
    mt = v.long_mt
  mt or= _mt
  setmetatable({
    byte1: byte1, :version, :dst_connection_id, :src_connection_id,
    data_off: _off, payload_off: _off, long_header: true
  }, mt), _off

--- Parses a short QUIC header from a binary string.
-- Extracts the destination connection ID and other fields.
-- @tparam string self The binary string containing the QUIC header.
-- @tparam number off Offset to start parsing from.
-- @tparam number byte1 The first byte of the header.
-- @tparam[opt] string dst_id The destination connection ID (optional).
-- @tparam[opt] string src_connection_id The source connection ID (optional).
-- @tparam[opt] number version The QUIC version (optional).
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse_short_header = (off, byte1, dst_id=nil, src_connection_id=nil, version=nil) =>
  local mt, dst_connection_id, _off
  if dst_id
    dst_connection_id, _off  = su ">c#{#dst_id}", @, off
  if v = versions[version]
    mt = v.short_mt
  mt or= _mt
  setmetatable({
    byte1: byte1, :version, :dst_connection_id, :src_connection_id,
    data_off: _off, payload_off: _off
  }, mt), _off

--- Parses a QUIC header from a binary string.
-- Determines whether the header is long or short and delegates to the appropriate parse function.
-- @tparam string self The binary string containing the QUIC header.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @param ... Additional arguments for parsing.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1, ...) =>
  byte1 = byte @, off
  if byte1 & HEADER_FORM == 0
    parse_short_header @, off+1, byte1, ...
  else
    parse_long_header @, off+1, byte1

:versions, :pack, :parse
