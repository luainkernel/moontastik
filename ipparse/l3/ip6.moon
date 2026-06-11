--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- IPv6 Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating IPv6 headers.
-- It includes functions for handling IPv6 addresses, converting between binary and readable formats,
-- and managing IPv6 network addresses.
--
-- ### IPv6 Header Structure
-- ```
-- IPv6 Header {
--   version (4): IP version (always 6 for IPv6).
--   traffic_class (8): Traffic Class.
--   flow_label (20): Flow Label.
--   payload_len (16): Payload Length (in bytes, excluding the header).
--   next_header (8): Next Header (e.g., TCP, UDP, or extension headers).
--   hop_limit (8): Hop Limit (similar to TTL in IPv4).
--   src (128): Source IPv6 Address.
--   dst (128): Destination IPv6 Address.
--   payload (variable): Payload data (e.g., transport-layer data or extension headers).
-- }
-- ```
--
-- References:
-- - RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
--
-- @module l3.ip6

:format, pack: sp, unpack: su = require "ipparse.lib.pack_compat"
unpack or= table.unpack
:checksum, :checksum6 = require"ipparse.l3.lib"
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"
{:need_bytes} = require "ipparse"

local s2ip6
--- Packs the IPv6 header and payload into a binary string.
-- Calculates the checksum and updates header fields like `payload_len`.
-- @tparam table self The IPv6 header object.
-- @treturn string Binary string representing the packed IPv6 header and payload.
pack = =>
  data = @data or ""
  if type(data) == "table"
    data.checksum = 0
    d = "#{data}"  -- Let the L4 payload recalculate its length
    data.checksum = checksum6 @src, @dst, @next_header, d
    data = "#{data}"
  @payload_len = #data
  @vtf or= bor(lshift(@version, 28), lshift(@traffic_class or 0, 20), @flow_label or 0)
  sp(">I4 I2 I1 I1 c16 c16", @vtf, @payload_len, @next_header, @hop_limit, @src, @dst) .. "#{@data or ''}"

_mt = __tostring: pack

--- Parses a binary string into an IPv6 header structure.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed IPv6 header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  return nil, off unless need_bytes @, off, 40
  vtf, payload_len, next_header, hop_limit, src, dst, data_off = su ">I4 I2 I1 I1 c16 c16", @, off
  setmetatable({
    :vtf, version: rshift(vtf, 28), traffic_class: band(rshift(vtf, 20), 0xff), flow_label: band(vtf, 0xfffff)
    :payload_len
    :next_header
    :hop_limit
    :src, :dst
    :off, :data_off
  }, _mt), data_off

--- Creates a new IPv6 header object.
-- Initializes the `vtf` field if not already set.
-- @tparam table self The IPv6 header object.
-- @tfield[opt=6] number version The IP version (should be 6).
-- @tfield[opt=0] number traffic_class The Traffic Class field.
-- @tfield[opt=0] number flow_label The Flow Label field.
-- @tfield[opt] number payload_len The length of the payload in bytes. (Calculated by `pack` if not provided)
-- @tfield[opt] number next_header The protocol number of the next header (e.g., TCP, UDP, or extension header).
-- @tfield[opt=64] number hop_limit The Hop Limit field.
-- @tfield string src The source IPv6 address (16 bytes).
-- @tfield string dst The destination IPv6 address (16 bytes).
-- @tfield[opt] string data The payload data.
-- @treturn table The new IPv6 header object.
new = =>
  @version or= 6
  assert @version == 6, "IPv6 only (got version #{@version})"
  @hop_limit or= 64
  @payload_len or= 0
  @next_header or= 0
  @traffic_class or= 0
  @flow_label or= 0
  -- Initialize vtf if version, traffic_class, and flow_label are provided and vtf isn't already set.
  -- Note: pack() will definitively calculate vtf from the version, traffic_class, and flow_label fields.
  -- This line is a convenience if user provides version, traffic_class, and flow_label.
  -- Set common defaults for other optional fields if not provided
  @vtf or= bor(lshift(@version, 28), lshift(@traffic_class or 0, 20), @flow_label or 0)
  setmetatable @, _mt

--- Parses a readable IPv6 address string into an array of 16-bit integers.
-- Handles zero compression (::) in the address.
-- @tparam string self The IPv6 address string.
-- @treturn {number} Array of 16-bit integers representing the IPv6 address.
parse_ip6 = =>
  head, tail = @match "^(.-)::(.-)$"
  parts = {}
  if head  -- "::" present: pad the middle with zero groups
    hs = [tonumber(p, 16) for p in head\gmatch "[^:]+"]
    ts = [tonumber(p, 16) for p in tail\gmatch "[^:]+"]
    for p in *hs
      parts[#parts+1] = p
    for _ = 1, 8 - #hs - #ts
      parts[#parts+1] = 0
    for p in *ts
      parts[#parts+1] = p
  else
    parts = [tonumber(p, 16) for p in @gmatch "[^:]+"]
  parts

--- Converts a binary IPv6 address to a readable string.
-- Compresses consecutive zero groups with :: according to RFC 5952.
-- @tparam string self The binary IPv6 address.
-- @treturn string IPv6 address as a string in the format "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx".
ip62s = =>
  parts = { su ">HHHH HHHH", @ }

  -- Find the longest run of consecutive zeros
  max_zero_start = 1
  max_zero_len = 0
  zero_start = 1
  zero_len = 0

  for i = 1, 8
    if parts[i] == 0
      if zero_len == 0
        zero_start = i
      zero_len += 1
    else
      if zero_len > max_zero_len
        max_zero_start = zero_start
        max_zero_len = zero_len
      zero_len = 0

  -- Check if the last run is the longest
  if zero_len > max_zero_len
    max_zero_start = zero_start
    max_zero_len = zero_len

  -- Only compress if we have at least 2 consecutive zeros
  if max_zero_len >= 2
    -- Build the compressed address in two parts
    before = {}
    after = {}

    for i = 1, 8
      if i < max_zero_start
        table.insert before, format "%x", parts[i]
      elseif i >= max_zero_start + max_zero_len
        table.insert after, format "%x", parts[i]

    before_str = table.concat before, ":"
    after_str = table.concat after, ":"

    -- Handle edge cases
    if #before == 0 and #after == 0
      return "::"
    elseif #before == 0
      return "::" .. after_str
    elseif #after == 0
      return before_str .. "::"
    else
      return before_str .. "::" .. after_str
  else
    -- No compression needed
    format "%x:%x:%x:%x:%x:%x:%x:%x", unpack parts

--- Converts a readable IPv6 address string to binary format.
-- @tparam string self The IPv6 address as a string in the format "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx".
-- @treturn string Binary string representing the IPv6 address.
s2ip6 = =>
  sp ">HHHH HHHH", unpack parse_ip6 @

--- Converts a binary IPv6 network address to a readable string.
-- @tparam string self The binary IPv6 network address.
-- @treturn string IPv6 network address as a string in the format "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/mask".
net62s = =>
  m, a, b, c, d, e, f, g, h = su ">B HHHH HHHH", @
  format "%x:%x:%x:%x:%x:%x:%x:%x/%d", a, b, c, d, e, f, g, h, m

--- Converts a readable IPv6 network address string to binary format.
-- @tparam string self The IPv6 network address as a string in the format "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/mask".
-- @treturn string Binary string representing the IPv6 network address.
s2net6 = =>
  @, mask = @match"([^/]*)/?([^/]*)$"
  sp ">B HHHH HHHH", (tonumber mask or 128), unpack parse_ip6 @

:parse, :new, :ip62s, :s2ip6, :net62s, :s2net6
