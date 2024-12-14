:bidirectional = require"ipparse.fun"

format: sf, pack: sp, rep: sr, unpack: su = string
:concat = table

header = (off, is_tcp) =>
  local size
  if is_tcp
    size, off = su ">H", off
    off += 1
  id, qr_opcode_aa_tc_rd, ra_z_rcode, qdcount, ancount, nscount, arcount, off = su ">H B B H H H H", @, off
  id, qr_opcode_aa_tc_rd, ra_z_rcode, qdcount, ancount, nscount, arcount, off, size

local labels
label = (off, dns_off=0) =>
  return if off+2 > #@
  size, pos, _off = su "B B", @, off
  if size == 0
    return nil, off+1
  elseif size & 0xC0 == 0
    su "s1", @, off
  else
    off = ((size & 0x3F) << 8) + pos
    concat(labels(@, dns_off+off), "."), _off, true

labels = (off, dns_off) =>
  lbls = {}
  for i = 1, 1024
    lbl, off, last = label @, off, dns_off
    break if last or not lbl
    lbls[i] = lbl
  lbls, off

question = (off, dns_off) =>
  lbls, off = labels @, off, dns_off
  qclass, qtype, off = su "H H", @, off
  concat(lbls, "."), qclass, qtype, off

questions = (off, qdcount, dns_off) =>
  q = {}
  for i = 1, qdcount
    qname, qtype, qclass, off = question @, off, dns_off
    q[i] = {qname, qtype, qclass}
  q, off

rr = (off, dns_off) =>
  lbls, off = labels @, off, dns_off
  rtype, rclass, ttl, rdata, off = su ">H H I4 s2", @, off
  concat(lbls, "."), rtype, rclass, ttl, rdata, off

rrs = (off, count, dns_off) =>
  r = {}
  for i = 1, count
    rname, rtype, rclass, ttl, rdata, off = rr @, off, dns_off
    r[i] = {rname, rtype, rclass, ttl, rdata}
  r, off

:header, :label, :labels, :question, :questions, :rr, :rrs, types: bidirectional {
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

