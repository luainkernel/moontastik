--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TCP Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating TCP headers.
-- It includes functions for handling TCP packets, managing flags, and calculating offsets.
--
-- ### TCP Header Structure
-- ```
-- TCP Header {
--   spt (16): Source Port.
--   dpt (16): Destination Port.
--   seq_n (32): Sequence Number.
--   ack_n (32): Acknowledgment Number.
--   header_len (4): Header Length (in 32-bit words).
--   flags (6): Flags:
--     - 0x01: FIN (Finish).
--     - 0x02: SYN (Synchronize).
--     - 0x04: RST (Reset).
--     - 0x08: PSH (Push).
--     - 0x10: ACK (Acknowledgment).
--     - 0x20: URG (Urgent).
--   window (16): Window Size.
--   checksum (16): Checksum for error detection.
--   urg_ptr (16): Urgent Pointer.
--   options (variable): Optional fields (if any).
--   payload (variable): Payload data.
-- }
-- ```
--
-- References:
-- - RFC 793: Transmission Control Protocol (TCP)
--
-- @module tcp

pack: sp, unpack: su, :sub, :upper = string
:bidirectional = require"ipparse.fun"

flags = bidirectional {
  FIN: 0x01
  SYN: 0x02
  RST: 0x04
  PSH: 0x08
  ACK: 0x10
  URG: 0x20
}
:FIN, :SYN, :RST, :PSH, :ACK, :URG = flags

--- Packs the TCP header and payload into a binary string.
-- Constructs the binary representation of the TCP header and appends options and payload data.
-- @tparam table self The TCP header object.
-- @treturn string Binary string representing the packed TCP header and payload.
pack = =>
  sp(">H H I4 I4 B B H H H", @spt, @dpt, @seq_n, @ack_n, @header_len, @flags, @window, @checksum, @urg_ptr) .. @options .. "#{@data or ''}"

_mt =
  --- Converts the TCP header object to a binary string.
  -- @treturn string Binary string representing the TCP header and payload.
  __tostring: pack

  --- Checks if a specific TCP flag is set.
  -- @tparam string k The flag name (e.g., "SYN", "ACK").
  -- @treturn boolean `true` if the flag is set, `false` otherwise.
  __index: (k) =>
    if flag = type(k) == "string" and upper k
      if flag = flags[flag]
        @flags & flag ~= 0

  --- Sets or clears a specific TCP flag.
  -- @tparam string k The flag name (e.g., "SYN", "ACK").
  -- @tparam boolean v `true` to set the flag, `false` to clear it.
  __newindex: (k, v) =>
    if flag = type(k) == "string" and upper k
      if flag = flags[flag]
        if v then @flags |= flag else @flags &= ~flag
        return
    rawset @, k, v

--- Parses a binary string into a TCP header structure.
-- Extracts the source port, destination port, sequence number, acknowledgment number, flags, and other fields.
-- @tparam string self The binary string containing the TCP header.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed TCP header as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  spt, dpt, seq_n, ack_n, header_len, _flags, window, checksum, urg_ptr, _off = su ">H H I4 I4 B B H H H", @, off
  data_off = off + ((header_len & 0xf0) >> 2)
  options = sub @, _off, data_off-1
  setmetatable({
    :spt, :dpt, :seq_n, :ack_n
    :off, :header_len, :data_off
    flags: _flags, :window, :checksum, :urg_ptr
    :options
  }, _mt), data_off

--- Creates a new TCP header object.
-- Initializes the TCP header object and sets its flags based on the provided fields.
-- @tparam table self The TCP header object.
-- @treturn table The new TCP header object.
new = =>
  @flags = (@flags or 0) | (@urg and URG) | (@ack and ACK) | (@psh and PSH) | (@rst and RST) | (@syn and SYN) | (@fin and FIN)
  setmetatable @, _mt

:flags, :parse, :new, :pack
