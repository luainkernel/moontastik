--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- DNS Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating DNS messages.
-- It supports DNS header parsing, question and resource record handling, and EDNS options.
--
-- ### Features
-- - Parse and pack DNS headers, questions, and resource records.
-- - Handle DNS label compression and decompression.
-- - Support for EDNS options and extended DNS error codes.
--
-- ### DNS Message Structure
-- A DNS message consists of the following sections:
--
-- 1. **Header**:
--    - Transaction ID (16 bits): Identifies the DNS query/response pair.
--    - Flags (16 bits): Contains fields such as `qr`, `opcode`, `aa`, `tc`, `rd`, `ra`, `z`, and `rcode`.
--    - QDCOUNT (16 bits): Number of entries in the Question section.
--    - ANCOUNT (16 bits): Number of entries in the Answer section.
--    - NSCOUNT (16 bits): Number of entries in the Authority section.
--    - ARCOUNT (16 bits): Number of entries in the Additional section.
--
-- 2. **Question Section**:
--    - QNAME (variable length): Fully qualified domain name (FQDN) being queried.
--    - QTYPE (16 bits): Type of query (e.g., `A`, `AAAA`, `MX`).
--    - QCLASS (16 bits): Class of query (e.g., `IN` for Internet).
--
-- 3. **Answer, Authority, and Additional Sections**:
--    - NAME (variable length): Domain name to which the resource record pertains.
--    - TYPE (16 bits): Type of resource record (e.g., `A`, `AAAA`, `MX`).
--    - CLASS (16 bits): Class of resource record (e.g., `IN` for Internet).
--    - TTL (32 bits): Time-to-live for the resource record.
--    - RDLENGTH (16 bits): Length of the RDATA field.
--    - RDATA (variable length): Resource data (e.g., IP address for `A` records).
--
-- ### DNS Label Compression
-- DNS messages use label compression to reduce message size. A label can either be:
-- 1. **Normal Label**:
--    - A sequence of characters prefixed by its length.
-- 2. **Compressed Label**:
--    - A pointer to a previously defined label in the message.
--    - Compressed labels are identified by the first two bits of the label length field being set to `11`.
--
-- This module provides utilities to parse and handle both normal and compressed labels. The `label` function parses a single label, while the `labels` function parses a sequence of labels into a fully qualified domain name (FQDN).
--
-- ### EDNS Options
-- EDNS (Extension Mechanisms for DNS) extends the capabilities of DNS by allowing additional options to be included in DNS messages.
-- These options are encoded in OPT pseudo-resource records in the Additional section of a DNS message.
--
-- Common EDNS options supported by this module:
-- - **Client Subnet (Code 8)**:
--   - Fields: `family`, `source_netmask`, `scope_netmask`, `subnet`.
--   - Used to specify the network of the client making the DNS query.
-- - **Requestor MAC (Code 65001)**:
--   - Fields: `mac`.
--   - Used to include the MAC address of the requestor.
-- - **Requestor MAC String (Code 65073)**:
--   - Fields: `macstr`.
--   - Similar to `Requestor MAC`, but includes the MAC address as a string.
--
-- This module provides utilities to parse and pack EDNS options, ensuring compliance with RFC 6891.
--
-- References:
-- - RFC 1035: Domain Names - Implementation and Specification
-- - RFC 6891: Extension Mechanisms for DNS (EDNS(0))
--
-- @module dns

:bidirectional, :zero_indexed = require"ipparse.fun"
pack: sp, unpack: su, :sub = string
:concat = table

--- Packs the DNS header into a binary string.
-- @tparam table self The DNS header object.
-- @treturn string Binary string representing the packed DNS header.
pack_header = =>
  (@size and sp(">H", @size) or "") .. sp ">H B B H H H H", @id, @qr_opcode_aa_tc_rd, @ra_z_rcode, @qdcount, @ancount, @nscount, @arcount

_header_mt =
  __tostring: pack_header
  __index: (flag) =>
    switch flag
      when "qr"
        @qr_opcode_aa_tc_rd & 0x80 ~= 0
      when "opcode"
        (@qr_opcode_aa_tc_rd >> 3) & 0xf ~= 0
      when "aa"
        @qr_opcode_aa_tc_rd & 0x04 ~= 0
      when "tc"
        @qr_opcode_aa_tc_rd & 0x02 ~= 0
      when "rd"
        @qr_opcode_aa_tc_rd & 0x01 ~= 0
      when "ra"
        @ra_z_rcode & 0x80 ~= 0
      when "z"
        (@ra_z_rcode >> 4) & 0x07 ~= 0
      when "rcode"
        @ra_z_rcode & 0x0f ~= 0
  __newindex: (flag, val) =>
    switch flag
      when "qr"
        if val then @qr_opcode_aa_tc_rd |= 0x80 else @qr_opcode_aa_tc_rd &= ~0x80
      when "opcode"
        @qr_opcode_aa_tc_rd = (@qr_opcode_aa_tc_rd & ~0x78) | ((val & 0xf) << 3)
      when "aa"
        if val then @qr_opcode_aa_tc_rd |= 0x04 else @qr_opcode_aa_tc_rd &= ~0x04
      when "tc"
        if val then @qr_opcode_aa_tc_rd |= 0x02 else @qr_opcode_aa_tc_rd &= ~0x02
      when "rd"
        if val then @qr_opcode_aa_tc_rd |= 0x01 else @qr_opcode_aa_tc_rd &= ~0x01
      when "z"
        @ra_z_rcode = (@ra_z_rcode & ~0x70) | ((val & 0x07) << 4)
      when "rcode"
        @ra_z_rcode = (@ra_z_rcode & ~0x0f) | (val & 0x0f)

--- Parses a DNS header from a binary string.
-- @tparam string self The binary string containing the DNS header.
-- @tparam number off The offset to start parsing from.
-- @tparam boolean is_tcp Whether the DNS message is over TCP (affects size field).
-- @treturn table Parsed DNS header as a table.
-- @treturn number The next offset after parsing.
parse_header = (off, is_tcp) =>  -- Accepts data string, offset and boolean; returns DNS header infos
  len = #@ - off
  local size
  if is_tcp
    return nil, "No DNS data" if len < 2
    size, off = su ">H", @, off
    len -= 2
  return nil, "No DNS data" if len < 12
  id, qr_opcode_aa_tc_rd, ra_z_rcode, qdcount, ancount, nscount, arcount, data_off = su ">H B B H H H H", @, off
  setmetatable({
    :id, :qr_opcode_aa_tc_rd, :ra_z_rcode
    :qdcount, :ancount, :nscount, :arcount
    :off, :data_off, :size
  }, _header_mt), data_off

local labels

--- Parses a single DNS label from a binary string.
-- Handles both normal labels and compressed labels.
-- @tparam string self The binary string containing the DNS label.
-- @tparam number off The offset to start parsing from.
-- @tparam[opt=1] number l7_off The layer 7 offset for label parsing (default is 1).
-- @treturn string|nil The parsed label as a string, or `nil` if the label is empty.
-- @treturn number The next offset after parsing.
-- @treturn[opt] boolean `true` if the label is compressed, `nil` otherwise.
label = (off, l7_off=1) =>
  return nil if off+2 > #@
  size, pos, _off = su "B B", @, off
  if size == 0  -- End of label
    return nil, off+1
  if size & 0xC0 == 0  -- Normal case
    return su "s1", @, off
  -- DNS label compression
  off = ((size & 0x3F) << 8) + pos
  concat(labels(@, l7_off+off, l7_off), "."), _off, true

--- Parses a sequence of DNS labels into a fully qualified domain name (FQDN).
-- Handles both normal and compressed labels.
-- @tparam string self The binary string containing the DNS labels.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @treturn table A table of parsed labels.
-- @treturn number The next offset after parsing.
labels = (off, l7_off) =>
  lbls = {}
  for i = 1, 1024  -- Arbitrary large limit to avoid infinite loops
    -- off is the current absolute offset in the input string (@)
    -- l7_off is the absolute offset of the start of the DNS message in @
    lbl_segment, next_parse_off, is_from_pointer = label @, off, l7_off
    if not lbl_segment -- Indicates end of name (00 byte) or a parsing error in label()
      off = next_parse_off -- Ensure 'off' is updated (e.g., past the 00 byte)
      break
    lbls[i] = lbl_segment -- Store the parsed label segment
    off = next_parse_off   -- Update 'off' to the position after the processed segment
    if is_from_pointer -- If the segment was resolved via a pointer, it's the complete name.
      break
  lbls, off

--- Packs a DNS question into a binary string.
-- @tparam table self The DNS question object.
-- @treturn string Binary string representing the packed DNS question.
pack_question = =>
  @qname .. sp ">H H", @qtype, @qclass

_question_mt = __tostring: pack_question

--- Parses a DNS question section from a binary string.
-- @tparam string self The binary string containing the DNS question section.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @treturn table Parsed DNS question as a table.
-- @treturn number The next offset after parsing.
parse_question = (off, l7_off) =>
  lbls, _off = labels @, off, l7_off
  qname = sub @, off, _off-1
  qtype, qclass, _off = su ">H H", @, _off
  setmetatable({name: concat(lbls, "."), :qname, :qtype, :qclass, :off, end_off: _off-1}, _question_mt), _off

parse_questions = (off, qdcount, l7_off) =>
  res = {}
  for i = 1, qdcount
    q, off = parse_question @, off, l7_off
    res[i] = q
  res, off

--- Packs a DNS resource record (RR) into a binary string.
-- @tparam table self The DNS resource record object.
-- @treturn string Binary string representing the packed DNS resource record.
pack_rr = =>
  @rname .. sp ">H H I4 s2", @rtype, @rclass, @ttl, @rdata

_rr_mt = __tostring: pack_rr

--- Parses a DNS resource record (RR) from a binary string.
-- @tparam string self The binary string containing the DNS resource record.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @treturn table Parsed DNS resource record as a table.
-- @treturn number The next offset after parsing.
parse_rr = (off, l7_off) =>
  lbls, _off = labels @, off, l7_off
  rname = sub @, off, _off-1
  rtype, rclass, ttl, rdata, _off = su ">H H I4 s2", @, _off
  setmetatable({name: concat(lbls, "."), :rname, :rtype, :rclass, :ttl, :rdata, :off, end_off: _off-1}, _rr_mt), _off

parse_rrs = (off, count, l7_off) =>
  res = {}
  for i = 1, count
    r, off = parse_rr @, off, l7_off
    res[i] = r
  res, off

pack_opt = =>
  sp ">Hs2", @code, "#{@data}"

edns_opts = {
  [8]:     {"client_subnet",     {"family", "source_netmask", "scope_netmask", "subnet"}, ">H B B "}
  [65001]: {"requestor_mac",     {"mac"}}
  [65073]: {"requestor_mac_str", {"macstr"}}
}
edns_opts[v[1]] = k for k, v in pairs edns_opts when type(k) == "number"

_opt_mt = __tostring: pack_opt

--- Parses an EDNS option from a binary string.
-- @tparam string self The binary string containing the EDNS option.
-- @tparam number off The offset to start parsing from.
-- @treturn table Parsed EDNS option as a table.
-- @treturn number The next offset after parsing.
parse_opt = (off=1) =>
  code, data, _off = su ">Hs2", @, off
  len = #data
  if opt_parser = edns_opts[code]
    {typ, fields, fmt} = opt_parser
    if fmt
      _data = {su fmt, data}
      _data[#_data] = sub data, _data[#_data]
      data = _data
    else data = {data}
    data.type = typ
    data[fields[i]] = data[i] for i = 1, #fields
    setmetatable data, __tostring: => fmt and sp(fmt, unpack [data[field] for field in *fields]) or @[1]
  else setmetatable {data}, __tostring: => @[1]
  setmetatable({:code, :len, :data}, _opt_mt), _off

--- Parses all EDNS options from a binary string.
-- @tparam string self The binary string containing the EDNS options.
-- @treturn table A table of parsed EDNS options.
parse_opts = =>
  opts, off = {}, 1
  while off < #@
    opts[#opts+1], off = parse_opt @, off
  opts

--- Packs a DNS message into a binary string.
-- @tparam table self The DNS message object.
-- @treturn string Binary string representing the packed DNS message.
pack = =>
  @header.qdcount = #@questions
  @header.ancount = #@answers
  @header.nscount = #@authorities
  @header.arcount = #@additionals
  questions = concat([pack_question q for q in *@questions])
  answers = concat([pack_rr r for r in *@answers])
  authorities = concat([pack_rr r for r in *@authorities])
  additionals = concat([pack_rr r for r in *@additionals])
  body = questions .. answers .. authorities .. additionals
  @header.size = 12 + #body
  pack_header(@header) .. body

_mt =
  __tostring: pack
  __index: (k) => @header[k]

--- Parses a DNS message from a binary string.
-- @tparam string self The binary string containing the DNS message.
-- @tparam number l7_off The layer 7 offset for parsing.
-- @tparam boolean is_tcp Whether the DNS message is over TCP.
-- @treturn table Parsed DNS message as a table.
-- @treturn number The next offset after parsing.
parse = (l7_off, is_tcp) =>
  header, _off = parse_header @, l7_off, is_tcp
  return nil, l7_off, "No DNS data" if not header
  questions, _off = parse_questions @, _off, header.qdcount, l7_off
  answers, _off = parse_rrs @, _off, header.ancount, l7_off
  authorities, _off = parse_rrs @, _off, header.nscount, l7_off
  additionals, _off = parse_rrs @, _off, header.arcount, l7_off
  setmetatable({
    :header, question: questions[1]  -- RFC 9619
    :questions, :answers, :authorities, :additionals
  }, _mt), _off

classes = bidirectional {"IN", "CS", "CH", "HS", "NONE"}

rcodes = bidirectional zero_indexed {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

types = bidirectional {
  "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL",
  "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN",
  "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT",
  "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK",
  "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3",
  "NSEC3PARAM", "TLSA", "SMIMEA", "Unassigned", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY",
  "CSYNC", "ZONEMD", "SVCB", "HTTPS", "DSYNC"
  [99]: "SPF",
  [108]: "EUI48",
  [109]: "EUI64",
  [249]: "TKEY",
  [250]: "TSIG",
  [251]: "IXFR",
  [252]: "AXFR",
  [253]: "MAILB",
  [254]: "MAILA",
  [255]: "ANY",
  [256]: "URI",
  [257]: "CAA",
  [258]: "AVC",
  [259]: "DOA",
  [260]: "AMTRELAY",
  [32768]: "TA",
  [32769]: "DLV"
}

ede_codes = bidirectional zero_indexed {
  "Other"
  "Unsupported_DNSKEY_Algorithm"
  "Unsupported_DS_Digest_Type"
  "Stale_Answer"
  "Forged_Answer"
  "DNSSEC_Indeterminate"
  "DNSSEC_Bogus"
  "Signature_Expired"
  "Signature_Not_Yet_Valid"
  "DNSKEY_Missing"
  "RRSIGs_Missing"
  "No_Zone_Key_Bit_Set"
  "NSEC_Missing"
  "Cached_Error"
  "Not_Ready"
  "Blocked"
  "Censored"
  "Filtered"
  "Prohibited"
  "Stale_NXDOMAIN_Answer"
  "Not_Authoritative"
  "Not_Supported"
  "No_Reachable_Authority"
  "Network_Error"
  "Invalid_Data"
}

{
  :parse, :pack
  :parse_header, :pack_header
  :label, :labels
  :parse_question, :pack_question, :parse_questions
  :classes
  :parse_rr, :pack_rr, :parse_rrs, :rcodes
  :parse_opt, :parse_opts, :edns_opts
  :types, :ede_codes
}
