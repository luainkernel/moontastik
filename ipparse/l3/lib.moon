--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
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
-- @module lib

pack: sp, unpack: su = string

--- Calculates the checksum for the given binary data.
-- The checksum is calculated using the one's complement sum of 16-bit words.
-- @tparam string self The binary data for which the checksum is calculated.
-- @treturn number The calculated checksum as a 16-bit integer.
checksum = =>
  cksm = 0
  @ ..= "\0" if #@ & 1 == 1  -- Pad with a null byte if the length is odd
  for i = 1, #@, 2
    cksm += su ">H", @, i
  -- Handle carry-over
  while true
    carry = cksm >> 16
    break if carry == 0
    cksm = (cksm & 0xFFFF) + carry
  -- Return the one's complement of the checksum
  ~cksm & 0xFFFF

:checksum
