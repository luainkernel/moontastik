--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
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
-- @module udp

pack: sp, unpack: su = string

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
-- @tparam string self The binary string containing the UDP header.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed UDP header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  spt, dpt, len, checksum, data_off = su ">H H H H", @, off
  setmetatable({:spt, :dpt, :len, :checksum, :off, :data_off}, _mt), data_off

--- Creates a new UDP header object.
-- Initializes the UDP header object and sets its metatable.
-- @tparam table self The UDP header object.
-- @treturn table The new UDP header object.
new = =>
  setmetatable @, _mt

:parse, :new, :pack
