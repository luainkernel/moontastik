--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- IPv4 Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating IPv4 headers.
-- It includes functions for handling IPv4 addresses, converting between binary and readable formats,
-- and managing IPv4 network addresses.
--
-- ### IPv4 Header Structure
-- ```
-- IPv4 Header {
--   version (4): IP version (always 4 for IPv4).
--   ihl (4): Internet Header Length (in 32-bit words).
--   tos (8): Type of Service.
--   total_len (16): Total Length (header + payload).
--   id (16): Identification.
--   ff (16):
--     - flags (3): Flags:
--       - 0x4000: Don't Fragment (DF).
--       - 0x2000: More Fragments (MF).
--     - frag_offset (13): Fragment Offset.
--   ttl (8): Time to Live.
--   protocol (8): Protocol (e.g., TCP, UDP).
--   checksum (16): Header Checksum.
--   src (32): Source IP Address.
--   dst (32): Destination IP Address.
--   options (variable): Optional fields (if any).
--   payload (variable): Payload data.
-- }
-- ```
--
-- References:
-- - RFC 791: Internet Protocol (IPv4)
-- - RFC 1122: Requirements for Internet Hosts - Communication Layers
--
-- @module ip4

:format, :sub, :upper, pack: sp, unpack: su = string
:checksum = require"ipparse.l3.lib"
:bidirectional = require"ipparse.fun"

flags =
  DF: 0x4000  -- Don't Fragment
  MF: 0x2000  -- More Fragments
flags = bidirectional flags

--- Packs the IPv4 header and payload into a binary string.
-- Calculates the checksum and updates header fields like `ihl` and `total_len`.
-- If `self.data` is present, it's assumed to be an object representing the L4 payload.
-- Its `__tostring` method will be called (potentially twice), and its `checksum` field
-- will be set after calculating the L4 checksum using the pseudo-header.
-- @tparam table self The IPv4 header object.
-- @treturn string Binary string representing the packed IPv4 header and payload.
pack = =>
  data = @data or ""
  if type(data) == "table"
    data.checksum = 0
    d = "#{data}"  -- Let the L4 payload recalculate its length
    data.checksum = checksum(sp ">c4c4 x B s2", @src, @dst, @protocol, d)  -- RFC793 Section 3.1
    data = "#{data}"
  header_len = 20 + #(@options or "")
  @total_len = header_len + #data
  @ihl = header_len >> 2
  @v_ihl = ((@version << 4) | @ihl) if @version
  @checksum = checksum sp(">BBHHHBBH c4c4", @v_ihl, @tos, @total_len, @id, @ff, @ttl, @protocol, 0, @src, @dst)..@options
  sp(">BBHHHBBH c4c4", @v_ihl, @tos, @total_len, @id, @ff, @ttl, @protocol, @checksum, @src, @dst) .. @options .. data

_mt =
  --- Converts the IPv4 header object to a binary string.
  -- @treturn string Binary string representing the IPv4 header and payload.
  __tostring: pack

  --- Checks if a specific IPv4 flag is set.
  -- @tparam string k The flag name (e.g., "DF", "MF").
  -- @treturn boolean `true` if the flag is set, `false` otherwise.
  __index: (k) =>
    if flag = type(k) == "string" and flags[upper k]
      (@ff & flag) ~= 0

  --- Sets or clears a specific IPv4 flag.
  -- @tparam string k The flag name (e.g., "DF", "MF").
  -- @tparam boolean v `true` to set the flag, `false` to clear it.
  __newindex: (k, v) =>
    if flag = type(k) == "string" and flags[upper k]
      if v then @ff |= flag else @ff &= ~flag
      return
    rawset @, k, v

--- Parses a binary string into an IPv4 header structure.
-- @tparam string self The binary string to parse.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed IPv4 header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  v_ihl, tos, total_len, id, ff, ttl, protocol, cksum, src, dst, _off = su ">BBHHHBBH c4c4", @, off
  version, ihl = v_ihl >> 4, v_ihl & 0x0f
  payload_off = ihl << 2
  data_off = off + payload_off
  options = sub @, _off, data_off-1
  setmetatable({
    :version, :ihl, :v_ihl, :off, :payload_off, :data_off
    :tos, :total_len, :id, :ff, :ttl
    :protocol, checksum: cksum, :src, :dst
    :options
  }, _mt), data_off

--- Creates a new IPv4 header object.
-- Initializes the `v_ihl` field if not already set.
-- @tparam table self The IPv4 header object, which can contain the fields below.
-- @tfield[opt=4] number version The IP version (should be 4).
-- @tfield[opt] number ihl The Internet Header Length in 32-bit words. (Calculated by `pack` if not provided)
-- @tfield[opt=0] number tos The Type of Service field.
-- @tfield[opt] number total_len The total length of the IP packet (header + payload). (Calculated by `pack` if not provided)
-- @tfield[opt=0] number id The identification field.
-- @tfield[opt=0] number ff The flags and fragment offset field. If not provided, it can be composed from DF, MF, and frag_offset.
-- @tfield[opt=64] number ttl The Time to Live field.
-- @tfield[opt] number protocol The protocol number of the next layer (e.g., TCP, UDP).
-- @tfield[opt] number checksum The header checksum. (Calculated by `pack` if not provided)
-- @tfield string src The source IPv4 address (4 bytes).
-- @tfield string dst The destination IPv4 address (4 bytes).
-- @tfield[opt] boolean DF Don't Fragment flag. Used to compose `ff` if `ff` is not set directly.
-- @tfield[opt] boolean MF More Fragments flag. Used to compose `ff` if `ff` is not set directly.
-- @tfield[opt=0] number frag_offset Fragment offset in 8-octet units (13 bits). Used to compose `ff` if `ff` is not set directly.
-- @tfield[opt=""] string options Optional IP header fields.
-- @tfield[opt=""] string data The payload data.
-- @treturn table The new IPv4 header object.
new = =>
  @version or= 4
  assert @version == 4, "IPv4 only"
  -- Initialize v_ihl if version and ihl are provided and v_ihl isn't already set.
  -- Note: pack() will definitively calculate ihl from the @options string and then v_ihl.
  -- This line is a convenience if user provides version and ihl.
  @v_ihl or= ((@version << 4) | (@ihl or 0))
  -- Initialize ff from DF, MF, frag_offset if ff isn't already set.
  -- If DF, MF, frag_offset are also nil/false, ff will default to 0.
  @ff or= ((@DF and flags.DF or 0) | (@MF and flags.MF or 0) | (@frag_offset or 0))
  -- Set common defaults for other optional fields if not provided
  @tos or= 0
  @id or= 0 -- Could be randomized, but 0 is a simple default for construction
  @ttl or= 64 -- A common default TTL
  -- protocol is intentionally not defaulted here as it's critical for L4.
  -- checksum, total_len, ihl are calculated by pack().

  setmetatable @, _mt

--- Converts an IPv4 address from binary format to a readable string.
-- @tparam string self The binary IPv4 address.
-- @treturn string IPv4 address as a string in the format "x.x.x.x".
ip42s = =>
  format "%d.%d.%d.%d", su "BBBB", @

--- Converts an IPv4 address from a readable string to binary format.
-- @tparam string self The IPv4 address as a string in the format "x.x.x.x".
-- @treturn string Binary string representing the IPv4 address.
s2ip4 = =>
  sp "BBBB", @match"(%d+)%.(%d+)%.(%d+)%.(%d+)"

--- Converts a binary IPv4 network address to a readable string.
-- @tparam string self The binary IPv4 network address.
-- @treturn string IPv4 network address as a string in the format "x.x.x.x/mask".
net42s = =>
  m, a, b, c, d = su "BBBBB", @
  format "%d.%d.%d.%d/%d", a, b, c, d, m

--- Converts a readable IPv4 network address to binary format.
-- @tparam string self The IPv4 network address as a string in the format "x.x.x.x/mask".
-- @treturn string Binary string representing the IPv4 network address.
s2net4 = =>
  b1, b2, b3, b4, mask = @match"(%d+)%.(%d+)%.(%d+)%.(%d+)/?(%d*)"
  sp "B BBBB", (tonumber(mask) or 32), tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4)

:parse, :new, :pack, :ip42s, :s2ip4, :net42s, :s2net4
