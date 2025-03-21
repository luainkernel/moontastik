:bidirectional = require"ipparse.fun"

format: sf, pack: sp, rep: sr, unpack: su = string
:concat = table

header = (off, is_tcp) =>  -- Accepts data string, offset and boolean; returns DNS header infos
  len = #@ - off
  local size
  if is_tcp
    return nil, "No DNS data" if len < 2
    size, off = su ">H", @, off
    len -= 2
  return nil, "No DNS data" if len < 12
  id, qr_opcode_aa_tc_rd, ra_z_rcode, qdcount, ancount, nscount, arcount, data_off = su ">H B B H H H H", @, off
  {
    :id
    qr: qr_opcode_aa_tc_rd & 0x80
    opcode: (qr_opcode_aa_tc_rd >> 3) & 0xf
    aa: qr_opcode_aa_tc_rd & 0x04
    tc: qr_opcode_aa_tc_rd & 0x02
    rd: qr_opcode_aa_tc_rd & 0x01
    ra: ra_z_rcode & 0x80
    z: (ra_z_rcode >> 4) & 0x07
    rcode: ra_z_rcode & 0x0f
    :qdcount, :ancount, :nscount, :arcount
    :off, :data_off, :size
  }, data_off

local labels
label = (off, l7_off=0) =>
  return nil if off+2 > #@
  size, pos, _off = su "B B", @, off
  if size == 0
    return nil, off+1
  elseif size & 0xC0 == 0
    su "s1", @, off
  else
    off = ((size & 0x3F) << 8) + pos
    concat(labels(@, l7_off+off), "."), _off, true

labels = (off, l7_off) =>
  lbls = {}
  for i = 1, 1024
    lbl, off, last = label @, off, l7_off
    break if last or not lbl
    lbls[i] = lbl
  lbls, off

question = (off, l7_off) =>
  lbls, _off = labels @, off, l7_off
  qclass, qtype, _off = su ">H H", @, _off
  {qname: concat(lbls, "."), :qtype, :qclass, :off, end_off: _off-1}, _off

questions = (off, qdcount, l7_off) =>
  res = {}
  for i = 1, qdcount
    q, off = question @, off, l7_off
    res[i] = q
  res, off

rr = (off, l7_off) =>
  lbls, off = labels @, off, l7_off
  rtype, rclass, ttl, rdata, _off = su ">H H I4 s2", @, off
  {rname: concat(lbls, "."), :rtype, :rclass, :ttl, :rdata, :off, end_off: _off-1}, _off

rrs = (off, count, l7_off) =>
  res = {}
  for i = 1, count
    r, off = rr @, off, l7_off
    res[i] = r
  res, off

classes = bidirectional {"IN", "CS", "CH", "HS", "NONE"}

rcodes = {"FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}
rcodes[0] = "NOERROR"
rcodes = bidirectional rcodes

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

ede_codes = {
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
ede_codes[0] = "Other"
ede_codes = bidirectional ede_codes

:header, :label, :labels, :question, :questions, :classes, :rr, :rrs, :rcodes, :types, :ede_codes

