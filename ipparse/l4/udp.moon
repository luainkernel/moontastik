--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- UDP Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating UDP headers.
-- It includes functions for handling UDP packets, calculating lengths, and managing checksum fields.
--
-- ### UDP Header Structure
-- ```
-- UDP Header {
--   spt (16): Source Port.
--   dpt (16): Destination Port.
--   len (16): Length (header + payload, in bytes).
--   checksum (16): Checksum for error detection.
--   payload (variable): Payload data.
-- }
-- ```
--
-- References:
-- - RFC 768: User Datagram Protocol (UDP)
--
-- @module l4.udp

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
{:need_bytes} = require "ipparse"
checksum6: l3_checksum6 = require "ipparse.l3.lib"

--- Packs the UDP header and payload into a binary string.
-- Calculates the total length of the UDP packet and constructs the binary representation.
-- @tparam table self The UDP header object.
-- @treturn string Binary string representing the packed UDP header and payload.
pack = =>
  @len = 8 + (@data and #"#{@data}" or 0)
  sp(">H H H H", @spt, @dpt, @len, @checksum) .. "#{@data or ''}"

_mt = __tostring: pack

--- Parses a binary string into a UDP header structure.
-- Extracts the source port, destination port, length, and checksum from the binary string.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed UDP header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  return nil, off unless need_bytes @, off, 8
  spt, dpt, len, csum, data_off = su ">H H H H", @, off
  setmetatable({:spt, :dpt, :len, checksum: csum, :off, :data_off}, _mt), data_off

--- Computes the UDP checksum over an IPv6 pseudo-header and UDP packet.
-- The caller must pass a UDP packet with checksum field set to 0.
-- @tparam string src 16-byte IPv6 source address.
-- @tparam string dst 16-byte IPv6 destination address.
-- @tparam string udp_pkt Full UDP packet (header + payload).
-- @treturn number 16-bit checksum (mapped to 0xFFFF when result is 0).
checksum6 = (src, dst, udp_pkt) ->
  csum = l3_checksum6 src, dst, 17, udp_pkt
  csum = 0xFFFF if csum == 0
  csum

--- Creates a new UDP header object.
-- Initializes the UDP header object and sets its metatable.
-- @tparam table self The UDP header object.
-- @treturn table The new UDP header object.
new = =>
  setmetatable @, _mt

:parse, :new, :pack, :checksum6
