--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- IP Header Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating IP headers.
-- It supports both IPv6 and IPv4, automatically determining the version and delegating to the appropriate functions.
-- Additionally, it includes utilities for working with IP addresses, subnets, and protocol constants.
--
-- ### Features
-- - Parse and pack IP headers (IPv6 and IPv4).
-- - Convert between binary and readable IP addresses.
-- - Handle subnets and check for containment of IPs or subnets.
-- - Provide protocol constants for common IP protocols.
--
-- References:
-- - RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
-- - RFC 791: Internet Protocol (IPv4)
--
-- @module ip

:bidirectional = require"ipparse.fun"
:IP6, :IP4 = require"ipparse.l2.ethernet".proto
parse: ip6, new: ip6_new, pack: ip6_pack, :ip62s, :s2ip6, :net62s, :s2net6 = require"ipparse.l3.ip6"
parse: ip4, new: ip4_new, pack: ip4_pack, :ip42s, :s2ip4, :net42s, :s2net4 = require"ipparse.l3.ip4"
:sub, unpack: su = string

--- Determines the IP version from a binary string.
-- @tparam string self The binary string containing the IP header.
-- @tparam number off The offset to start reading from.
-- @treturn number The IP version (4 or 6).
get_version = (off) =>
  su("B", @, off) >> 4

--- Packs the IP data into a binary string.
-- Delegates to the appropriate IPv4 or IPv6 pack function based on the version.
-- @tparam table self The IP header object.
-- @treturn string Binary string representing the packed IP header and payload.
pack = =>
  @version == 6 and ip6_pack(@) or ip4_pack(@)

--- Parses a binary string into an IP header structure.
-- Determines the IP version and delegates to the appropriate IPv4 or IPv6 parse function.
-- @tparam string self The binary string containing the IP header.
-- @tparam number off The offset to start parsing from.
-- @tparam[opt] number eth_proto The Ethernet protocol (optional).
-- @treturn table Parsed IP header as a table.
parse = (off, eth_proto) =>
  local res, _off
  v = eth_proto or get_version @, off
  switch v
    when IP6
      res, _off = ip6 @, off
    when IP4
      res, _off = ip4 @, off
    else return nil, "Unknown IP version #{v} at offset #{off}"
  return nil, "Failed to parse IP header" if not res -- Should not happen if version is known
  header_len = res.data_off - res.off
  res.total_len or= res.payload_len + header_len
  res.payload_len or= res.total_len - header_len
  res.next_header or= res.protocol
  res.protocol or= res.next_header
  res, _off

--- Creates a new IP header object.
-- Delegates to the appropriate IPv4 or IPv6 constructor based on the version.
-- @tparam table self The IP header object.
-- @treturn table The new IP header object.
new = =>
  @version == 6 and ip6_new(@) or ip4_new(@)

--- Converts a binary IP address to a readable string.
-- @tparam string self The binary IP address.
-- @treturn string The IP address as a readable string.
ip2s = =>
  (#@ == 16 and ip62s or #@ == 4 and ip42s) @

--- Converts a readable IP address string to binary format.
-- @tparam string self The readable IP address string.
-- @treturn string The binary IP address.
s2ip = =>
  @match":" and s2ip6(@) or s2ip4(@)

--- Converts a binary subnet to a readable string.
-- @tparam string self The binary subnet.
-- @treturn string The subnet as a readable string.
net2s = =>
  (#@ == 17 and net62s or #@ == 5 and net42s) @

--- Converts a readable subnet string to binary format.
-- @tparam string self The readable subnet string.
-- @treturn string The binary subnet.
s2net = =>
  (@match":" and s2net6 or @match"%." and s2net4) @

--- Checks whether a network contains a specific IP address.
-- @tparam string self The binary network address.
-- @tparam string i The binary IP address.
-- @tparam[opt] number nmask The network mask (optional).
-- @treturn boolean `true` if the network contains the IP, `false` otherwise.
contains_ip = (i, nmask) =>
  if not nmask
    return false if #@ ~= #i+1
    nmask = su "B", @
    return sub(@, 2) == i if nmask == (#i << 3)
  fmt, shft = "c#{nmask >> 3}B", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, i
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

--- Checks whether a network contains a specific subnet.
-- @tparam string self The binary network address.
-- @tparam string subnet The binary subnet address.
-- @treturn boolean `true` if the network contains the subnet, `false` otherwise.
contains_subnet = (subnet) =>
  return false if #@ ~= #subnet
  nmask, smask = su("B", @), su("B", subnet)
  return false if nmask > smask
  return @ == subnet if nmask == smask
  contains_ip @, sub(subnet, 2), nmask

--- Protocol constants for common IP protocols.
-- @field ICMP Internet Control Message Protocol (0x01).
-- @field TCP Transmission Control Protocol (0x06).
-- @field UDP User Datagram Protocol (0x11).
-- @field GRE Generic Routing Encapsulation (0x2F).
-- @field ESP Encapsulating Security Payload (0x32).
-- @field ICMPv6 Internet Control Message Protocol for IPv6 (0x3A).
-- @field OSPF Open Shortest Path First (0x59).
proto = bidirectional {
  "ICMP":   0x01
  "TCP":    0x06
  "UDP":    0x11
  "GRE":    0x2F
  "ESP":    0x32
  "ICMPv6": 0x3A
  "OSPF":   0x59
}

:get_version, :parse, :new, :pack, :proto, :ip2s, :s2ip, :net2s, :s2net, :contains_subnet, :contains_ip
