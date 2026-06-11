--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
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
-- @module l4.quic

pack: sp, unpack: su, :byte = require "ipparse.lib.pack_compat"
unpack = table.unpack or unpack
{:need_bytes} = require "ipparse"
:bidirectional = require"ipparse.fun"
{:band} = require"ipparse.lib.bit_compat"
{:parse_varint} = require"ipparse.l4.quic.frames"

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
-- Extracts the version, destination connection ID, source connection ID,
-- and (for Initial packets, RFC 9001) the token and length fields.
-- @tparam number off Offset to start parsing from.
-- @tparam number byte1 The first byte of the header.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse_long_header = (off, byte1) =>
  return nil, off unless need_bytes @, off, 6  -- version (4) + 2 CID length bytes
  ok, version, dst_connection_id, src_connection_id, _off = pcall su, ">I4 s1 s1", @, off
  return nil, off unless ok
  local mt
  local pkt_type, token, pkt_length
  if v = versions[version]
    mt = v.long_mt
    -- Packet type is bits 4-5 of byte1 (RFC 9000 §17.2)
    pkt_type = band(byte1, 0x30)
  mt or= _mt

  -- Initial packets (pkt_type == 0x00) carry a token field (RFC 9001 §17.2.2)
  if pkt_type == 0x00
    token_len, _off = parse_varint @, _off
    return nil, off unless token_len and need_bytes @, _off, token_len
    token = @\sub _off, _off + token_len - 1
    _off += token_len

  -- All long-header packet types carry a Length VarInt (except Retry)
  if pkt_type != 0x30  -- 0x30 = Retry
    pkt_length, _off = parse_varint @, _off
    return nil, off unless pkt_length

  setmetatable({
    byte1: byte1, :version, :dst_connection_id, :src_connection_id,
    :token, :pkt_length, pkt_type: pkt_type,
    pn_off: _off,        -- 1-based offset of the (protected) packet number field
    data_off: _off, payload_off: _off, long_header: true
  }, mt), _off

--- Parses a short QUIC header from a binary string.
-- Extracts the destination connection ID and other fields.
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
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @param ... Additional arguments for parsing.
-- @treturn table Parsed QUIC header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1, ...) =>
  byte1 = byte @, off
  return nil, off unless byte1
  if band(byte1, HEADER_FORM) == 0
    parse_short_header @, off+1, byte1, ...
  else
    parse_long_header @, off+1, byte1

--- Splits a UDP payload into QUIC datagrams when packets are coalesced.
-- Returns one item per parsed QUIC packet with bounds and raw bytes.
-- @tparam[opt=1] number off Offset to start parsing from.
-- @param ... Additional arguments forwarded to `parse`.
-- @treturn {table}|nil Array of `{ header, off, packet_end, data }`.
-- @treturn string|nil Error string on failure.
split_datagrams = (off=1, ...) =>
  frame = @
  args = {...}
  packets = {}
  while off <= #frame
    q, err = parse frame, off, unpack args
    return nil, "QUIC header parse error at offset #{off}: #{err}" unless q
    return nil, "unsupported QUIC short header at offset #{off}" unless q.long_header
    return nil, "missing QUIC packet number offset at offset #{off}" unless q.pn_off
    return nil, "missing QUIC packet length at offset #{off}" unless q.pkt_length

    packet_end = (q.pn_off - 1) + q.pkt_length
    return nil, "invalid QUIC packet bounds at offset #{off}" unless packet_end >= off and packet_end <= #frame
    packets[#packets + 1] = header: q, :off, :packet_end, data: frame\sub(off, packet_end)
    off = packet_end + 1
  packets

:versions, :pack, :parse, :split_datagrams
