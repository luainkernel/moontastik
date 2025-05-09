--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Ethernet Frame Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating Ethernet frames.
-- It includes functions for handling Ethernet headers, MAC address conversions, and protocol constants.
--
-- # Ethernet Frame Structure
--
-- ```
-- Ethernet Frame {
--   dst (48): Destination MAC Address.
--   src (48): Source MAC Address.
--   protocol (16): EtherType (e.g., 0x86DD for IPv6, 0x0800 for IPv4).
--   payload (variable): Frame payload (e.g., IP packet).
-- }
-- ```
--
-- References:
--
-- - RFC 894: Standard for the Transmission of IP Datagrams over Ethernet Networks
-- - IEEE 802.3: Ethernet Standards
--
-- @module ethernet

:bidirectional = require"ipparse.fun"
:format, pack: sp, unpack: su = string
:unpack = table

--- Packs the Ethernet frame fields into a binary string.
-- Constructs the binary representation of the Ethernet frame, including destination MAC, source MAC, EtherType, and optional payload data.
-- @tparam table self The Ethernet frame object.
-- @treturn string The packed Ethernet frame as a binary string.
pack = => sp("c6 c6 >H", @dst, @src, @protocol) .. "#{@data or ''}"

_mt =
  --- Converts the Ethernet frame object to a binary string.
  -- @treturn string Binary string representing the Ethernet frame.
  __tostring: pack

--- Parses an Ethernet frame header from a data string.
-- Extracts the destination MAC, source MAC, EtherType, and calculates offsets for the payload.
-- @tparam string self The binary string containing the Ethernet frame.
-- @tparam[opt=1] number off Offset in the data string to start parsing from. Defaults to 1.
-- @treturn table A table containing the Ethernet header fields: `dst` (destination MAC), `src` (source MAC), `protocol` (EtherType), `off` (input offset), `data_off` (offset after header).
-- @treturn number The offset after the Ethernet header (data_off).
parse = (off=1) =>
  dst, src, protocol, data_off = su "c6 c6 >H", @, off
  setmetatable({:dst, :src, :protocol, :off, :data_off}, _mt), data_off

--- Creates a new instance of the Ethernet frame object and sets its metatable.
-- @tparam table self The Ethernet frame object.
-- @treturn table The new Ethernet frame object with the appropriate metatable set.
new = =>
  setmetatable @, _mt

--- Converts a binary MAC address to a human-readable string.
-- Converts six bytes of binary data into a colon-separated MAC address string.
-- @tparam string self Six bytes representing the MAC address.
-- @treturn string A string formatted as "xx:xx:xx:xx:xx:xx".
mac2s = =>
  format "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", su "BBBBBB", @

--- Converts a human-readable MAC address string to a binary data string.
-- Converts a colon-separated MAC address string into six bytes of binary data.
-- @tparam string s The MAC address in colon-separated hexadecimal format (e.g., "AA:BB:CC:DD:EE:FF").
-- @treturn string The MAC address as a binary data string.
s2mac = =>
  sp "BBBBBB", unpack [tonumber(s, 16) for s in @gmatch"[^:]+"]

--- Protocol numbers as found in the Ethernet header.
-- These constants represent common EtherType values used in Ethernet frames.
-- @field[type=number] IP6 The protocol number for IPv6 (0x86DD).
-- @field[type=number] IP4 The protocol number for IPv4 (0x0800).
proto =
  IP6: 0x86DD
  IP4: 0x800
proto = bidirectional proto

:parse, :new, :pack, :proto, :mac2s, :s2mac
