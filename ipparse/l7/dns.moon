-- +---------------------------+
-- |         Header           |
-- +---------------------------+
-- |  Transaction ID (16 bits) |
-- |  Flags (16 bits)          | qr, opcode, aa, tc, rd, ra, z, rcode
-- |  QDCOUNT (16 bits)        |
-- |  ANCOUNT (16 bits)        |
-- |  NSCOUNT (16 bits)        |
-- |  ARCOUNT (16 bits)        |
-- +---------------------------+
-- |         Question          |
-- +---------------------------+
-- |  QNAME (variable length)  |
-- |  QTYPE (16 bits)          |
-- |  QCLASS (16 bits)         |
-- +---------------------------+
-- |      Answer (each)        | idem for each Authority and Additional (which are optional)
-- +---------------------------+
-- |  NAME (variable length)   |
-- |  TYPE (16 bits)           |
-- |  CLASS (16 bits)          |
-- |  TTL (32 bits)            |
-- |  RDLENGTH (16 bits)       |
-- |  RDATA (variable length)  |
-- +---------------------------+

:bidirectional, :zero_indexed = require"ipparse.fun"

pack:sp, unpack: su, :sub = string
:concat = table

pack_header = =>
  (@size and sp(">H", @size) or "") .. sp ">H B B H H H H", @id, @qr_opcode_aa_tc_rd, @ra_z_rcode, @qdcount, @ancount, @nscount, @arcount

_header_mt =
  __tostring: pack_header
  __index: (flag) =>
    switch flag
      when "qr"
        @qr_opcode_aa_tc_rd & 0x80
      when "opcode"
        (@qr_opcode_aa_tc_rd >> 3) & 0xf
      when "aa"
        @qr_opcode_aa_tc_rd & 0x04
      when "tc"
        @qr_opcode_aa_tc_rd & 0x02
      when "rd"
        @qr_opcode_aa_tc_rd & 0x01
      when "ra"
        @ra_z_rcode & 0x80
      when "z"
        (@ra_z_rcode >> 4) & 0x07
      when "rcode"
        @ra_z_rcode & 0x0f
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

labels = (off, l7_off) =>
  lbls = {}
  for i = 1, 1024  -- Arbitrary large limit to avoid infinite loops
    lbl, off, last = label @, off, l7_off
    break if last or not lbl
    lbls[i] = lbl
  lbls, off

pack_question = =>
  @qname .. sp ">H H", @qtype, @qclass

_question_mt = __tostring: pack_question

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

pack_rr = =>
  @rname .. sp ">H H I4 s2", @rtype, @rclass, @ttl, @rdata

_rr_mt = __tostring: pack_rr

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

_mt = __tostring: pack

parse = (off, is_tcp) =>
  header, _off = parse_header @, off, is_tcp
  return nil, off, "No DNS data" if not header
  questions, _off = parse_questions @, _off, header.qdcount, off
  answers, _off = parse_rrs @, _off, header.ancount, off
  authorities, _off = parse_rrs @, _off, header.nscount, off
  additionals, _off = parse_rrs @, _off, header.arcount, off
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
  "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY",
  "CSYNC", "ZONEMD", "SVCB", "HTTPS", "SPF", "EUI48", "EUI64", "TKEY", "TSIG", "IXFR",
  "AXFR", "MAILB", "MAILA", "ANY", "URI", "CAA", "AVC", "DOA", "AMTRELAY", "TA",
  "DLV"
}

ede_codes = bidirectional zero_indexed {
  "Other"
  "Unsupported_DNSKEY_Algorithm",
  "Unsupported_DS_Digest_Type",
  "Stale_Answer",
  "Forged_Answer",
  "DNSSEC_Indeterminate",
  "DNSSEC_Bogus",
  "Signature_Expired",
  "Signature_Not_Yet_Valid",
  "DNSKEY_Missing",
  "RRSIGs_Missing",
  "No_Zone_Key_Bit_Set",
  "NSEC_Missing",
  "Cached_Error",
  "Not_Ready",
  "Blocked",
  "Censored",
  "Filtered",
  "Prohibited",
  "Stale_NXDOMAIN_Answer",
  "Not_Authoritative",
  "Not_Supported",
  "No_Reachable_Authority",
  "Network_Error",
  "Invalid_Data"
}

:parse, :pack, :parse_header, :pack_header, :label, :labels, :parse_question, :pack_question, :parse_questions, :classes, :parse_rr, :pack_rr, :parse_rrs, :rcodes, :types, :ede_codes
