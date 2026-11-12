--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Utility Functions for IP Protocols
-- This module provides utility functions for IP-related operations, such as checksum calculation
-- and pseudo-header construction. These utilities are used in higher-level modules for handling
-- IPv4, IPv6, and transport-layer protocols.
--
-- ### Functions
-- - `pseudo_header`: Constructs a pseudo-header for checksum calculation.
-- - `checksum`: Calculates the checksum for binary data.
--
-- References:
-- - RFC 791: Internet Protocol (IPv4)
-- - RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
-- - RFC 1071: Computing the Internet Checksum
--
-- @module l3.lib

pack: sp = require "ipparse.lib.pack_compat"
:byte = string
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"

--- Calculates the checksum for the given binary data.
-- The checksum is calculated using the one's complement sum of 16-bit words.
-- Reads the words directly with `string.byte` (no per-word `string.unpack`
-- call, no padded copy for odd lengths); the accumulation is identical to
-- summing `unpack ">H"` over each word.
-- @tparam string self The binary data for which the checksum is calculated.
-- @treturn number The calculated checksum as a 16-bit integer.
checksum = =>
  len = #@
  even = len - band(len, 1)   -- borne de la partie paire : le dernier octet
  cksm = 0                    -- d'une longueur impaire vaut 0x??00
  for i = 1, even, 2
    a, b = byte @, i, i + 1
    cksm += a * 256 + b
  cksm += byte(@, len) * 256 if even < len
  -- Handle carry-over
  while true
    carry = rshift(cksm, 16)
    break if carry == 0
    cksm = band(cksm, 0xFFFF) + carry
  -- Return the one's complement of the checksum
  band(bnot(cksm), 0xFFFF)

--- Computes a transport checksum over the IPv6 pseudo-header and payload bytes.
-- RFC8200 Section 8.1 (Upper-Layer Checksums).
-- @tparam string src 16-byte IPv6 source address.
-- @tparam string dst 16-byte IPv6 destination address.
-- @tparam number next_header Next Header value (e.g. 17 for UDP, 6 for TCP).
-- @tparam string payload Transport payload (header + data for checksum context).
-- @treturn number 16-bit checksum.
checksum6 = (src, dst, next_header, payload) ->
  checksum sp(">c16c16 I4 xxx B", src, dst, #payload, next_header) .. payload

:checksum, :checksum6
