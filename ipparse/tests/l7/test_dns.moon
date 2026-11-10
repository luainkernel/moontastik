--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
dns = require"ipparse.l7.dns"
{:hex2bin} = require"ipparse.init"

-- DNS query: ID=0x1234, RD=1, QDCOUNT=1, QNAME=example.com, QTYPE=A, QCLASS=IN
dns_query = hex2bin "123401000001000000000000076578616d706c6503636f6d0000010001"

-- DNS response: ID=0x1234, QR=1,RD=1,RA=1, QDCOUNT=1, ANCOUNT=1
-- Question: example.com A IN
-- Answer: ptr c00c, TYPE=A, CLASS=IN, TTL=3600, RDATA=93.184.216.34
dns_response = hex2bin(
  "123481800001000100000000" ..  -- header
  "076578616d706c6503636f6d00" .. -- QNAME: example.com
  "00010001" ..                   -- QTYPE=A, QCLASS=IN
  "c00c" ..                       -- answer NAME: pointer to offset 12
  "00010001" ..                   -- TYPE=A, CLASS=IN
  "00000e10" ..                   -- TTL=3600
  "0004" ..                       -- RDLEN=4
  "5db8d822"                      -- RDATA=93.184.216.34
)

dns_loop_pointer = hex2bin(
  "000101000001000000000000" .. -- header
  "c00c" ..                     -- qname points to itself (loop)
  "00010001"
)

dns_truncated_label = hex2bin(
  "000101000001000000000000" .. -- header
  "056162"                       -- says label len=5, provides only 2 bytes
)

test "parse_header extracts id", ->
  header, _ = dns.parse_header dns_query, 1, false
  assert header ~= nil, "parse_header should not return nil"
  assert header.id == 0x1234, "id should be 0x1234, got #{header.id}"

test "parse_header extracts qdcount", ->
  header, _ = dns.parse_header dns_query, 1, false
  assert header.qdcount == 1, "qdcount should be 1, got #{header.qdcount}"

test "header rd flag is set", ->
  header, _ = dns.parse_header dns_query, 1, false
  assert header.rd == true, "rd flag should be true"

test "header qr flag is false for query", ->
  header, _ = dns.parse_header dns_query, 1, false
  assert header.qr == false, "qr should be false for a query"

test "parse returns question name", ->
  msg, _ = dns.parse dns_query, 1, false
  assert msg ~= nil, "parse should not return nil"
  assert msg.question ~= nil, "question should not be nil"
  assert msg.question.name == "example.com", "question name should be 'example.com', got '#{msg.question.name}'"

test "question qtype is A", ->
  msg, _ = dns.parse dns_query, 1, false
  assert dns.types[msg.question.qtype] == "A", "qtype should be A, got '#{dns.types[msg.question.qtype]}'"

test "question qclass is IN", ->
  msg, _ = dns.parse dns_query, 1, false
  assert dns.classes[msg.question.qclass] == "IN", "qclass should be IN, got '#{dns.classes[msg.question.qclass]}'"

test "parse response: header qr flag is true", ->
  msg, _ = dns.parse dns_response, 1, false
  assert msg.header.qr == true, "qr should be true for a response"

test "parse response: header ra flag is true", ->
  msg, _ = dns.parse dns_response, 1, false
  assert msg.header.ra == true, "ra flag should be true"

test "parse response: ancount == 1", ->
  msg, _ = dns.parse dns_response, 1, false
  assert msg.header.ancount == 1, "ancount should be 1, got #{msg.header.ancount}"

test "label compression: answer name is example.com", ->
  msg, _ = dns.parse dns_response, 1, false
  assert #msg.answers >= 1, "should have at least 1 answer"
  assert msg.answers[1].name == "example.com", "answer name should be 'example.com', got '#{msg.answers[1].name}'"

test "answer rtype is A", ->
  msg, _ = dns.parse dns_response, 1, false
  assert dns.types[msg.answers[1].rtype] == "A", "answer rtype should be A"

test "answer rclass is IN", ->
  msg, _ = dns.parse dns_response, 1, false
  assert dns.classes[msg.answers[1].rclass] == "IN", "answer rclass should be IN"

test "answer ttl is 3600", ->
  msg, _ = dns.parse dns_response, 1, false
  assert msg.answers[1].ttl == 3600, "ttl should be 3600, got #{msg.answers[1].ttl}"

test "answer rdata is 93.184.216.34", ->
  msg, _ = dns.parse dns_response, 1, false
  assert msg.answers[1].rdata == "\093\184\216\034", "rdata mismatch"

test "types bidirectional: types[1] == 'A'", ->
  assert dns.types[1] == "A", "types[1] should be 'A', got '#{dns.types[1]}'"

test "types bidirectional: types['A'] == 1", ->
  assert dns.types["A"] == 1, "types['A'] should be 1, got #{dns.types['A']}"

test "classes bidirectional: classes[1] == 'IN'", ->
  assert dns.classes[1] == "IN", "classes[1] should be 'IN', got '#{dns.classes[1]}'"

test "classes bidirectional: classes['IN'] == 1", ->
  assert dns.classes["IN"] == 1, "classes['IN'] should be 1, got #{dns.classes['IN']}"

test "parse fails safely on compression pointer loop", ->
  msg, _, err = dns.parse dns_loop_pointer, 1, false
  assert msg == nil, "expected parse failure"
  assert err and err\match("loop"), "expected pointer loop error, got #{err}"

test "parse fails safely on truncated label", ->
  msg, _, err = dns.parse dns_truncated_label, 1, false
  assert msg == nil, "expected parse failure"
  assert err and err\match("truncated DNS label"), "expected truncated label error, got #{err}"

-- Response with two A answers (compressed owner names) and an EDNS OPT record.
dns_response_2a_opt = hex2bin(
  "abcd81800001000200000001" ..
  "076578616d706c6503636f6d00" ..
  "00010001" ..
  "c00c000100010000012c00045db8d822" ..
  "c00c000100010000012c00045db8d823" ..
  "0000291000000000000000"
)

-- Response with non-empty authority and additional sections.
dns_response_sections = hex2bin(
  "123481800001000100010001" ..
  "076578616d706c6503636f6d00" ..
  "00010001" ..
  "c00c000100010000003c000401020304" ..
  "c00c000200010000003c0011" ..
  "036e7331076578616d706c6503636f6d00" ..
  "c00c000100010000003c000405060708"
)

-- Question with several uncompressed labels.
dns_long_name_query = hex2bin(
  "000101000001000000000000" ..
  "03777777076578616d706c6509737562646f6d61696e0474657374056c6f63616c00" ..
  "00010001"
)

-- Same long question, answer owner name is a pointer to offset 12.
dns_long_name_answer = hex2bin(
  "000181800001000100000000" ..
  "03777777076578616d706c6509737562646f6d61696e0474657374056c6f63616c00" ..
  "00010001" ..
  "c00c000100010000003c000401020304"
)

-- A simple query prefixed with its 2-byte TCP length (29 bytes).
dns_tcp_query = hex2bin("001d" .. "123401000001000000000000076578616d706c6503636f6d0000010001")

test "byte-exact round-trip: two A answers + EDNS OPT", ->
  assert tostring(dns.parse(dns_response_2a_opt, 1)) == dns_response_2a_opt

test "byte-exact round-trip: simple query", ->
  assert tostring(dns.parse(dns_query, 1)) == dns_query

test "byte-exact round-trip: authority and additional sections", ->
  assert tostring(dns.parse(dns_response_sections, 1)) == dns_response_sections

test "byte-exact round-trip: TCP message with size prefix", ->
  assert tostring(dns.parse(dns_tcp_query, 1, true)) == dns_tcp_query

test "byte-exact round-trip: long uncompressed name", ->
  assert tostring(dns.parse(dns_long_name_query, 1)) == dns_long_name_query

test "long uncompressed name decodes all labels", ->
  msg, _ = dns.parse dns_long_name_query, 1, false
  assert msg.question.name == "www.example.subdomain.test.local",
    "got '#{msg.question.name}'"

test "compression pointer answer decodes full name", ->
  msg, _ = dns.parse dns_long_name_answer, 1, false
  assert msg.answers[1].name == "www.example.subdomain.test.local",
    "got '#{msg.answers[1].name}'"

test "header accessors return numeric opcode, z and rcode", ->
  h = dns.new_header {}
  h.opcode = 5
  h.z = 2
  h.rcode = 3
  assert h.opcode == 5, "opcode should be 5, got #{h.opcode}"
  assert h.z == 2, "z should be 2, got #{h.z}"
  assert h.rcode == 3, "rcode should be 3, got #{h.rcode}"
  h.qr = true
  assert h.qr == true, "qr should stay boolean"

test "header ra accessor is writable", ->
  h = dns.new_header {ra: true}
  assert h.ra == true, "ra should be true"
  assert h.ra_z_rcode == 0x80, "ra bit should be 0x80, got #{h.ra_z_rcode}"
  h.ra = false
  assert h.ra == false, "ra should be false"
  assert h.ra_z_rcode == 0, "ra bit should be cleared, got #{h.ra_z_rcode}"

test "header stores unknown fields instead of dropping them", ->
  h = dns.new_header {size: 40}
  assert rawget(h, "size") == 40, "size should be stored, got #{rawget(h, 'size')}"

test "pack emits size prefix when size is preset", ->
  msg = dns.new {header: dns.new_header {size: 0}}
  packed = tostring msg
  assert #packed == 14, "packed length should be 14, got #{#packed}"
  assert packed\sub(1, 2) == "\000\012", "prefix should be 12"

test "unknown EDNS option round-trips byte-exact", ->
  raw = "\000\010\000\002hi"
  o = dns.parse_opt raw
  assert o.data ~= nil, "unknown option data should not be nil"
  assert tostring(o) == raw, "unknown option should round-trip"

test "EDNS client_subnet round-trips byte-exact", ->
  raw = "\000\008\000\007\000\001\024\000\192\168\001"
  o = dns.parse_opt raw
  assert o.data.subnet == "\192\168\001", "subnet should be preserved"
  assert tostring(o) == raw, "client_subnet option should round-trip"

test "EDNS client_subnet reflects modified fields", ->
  o = dns.parse_opt "\000\008\000\007\000\001\024\000\192\168\001"
  o.data.source_netmask = 16
  assert tostring(o) == "\000\008\000\007\000\001\016\000\192\168\001",
    "modified source_netmask should be packed"

test "classes NONE and ANY use RFC values", ->
  assert dns.classes.NONE == 254, "NONE should be 254, got #{dns.classes.NONE}"
  assert dns.classes.ANY == 255, "ANY should be 255, got #{dns.classes.ANY}"
  assert dns.classes[1] == "IN", "classes[1] should be 'IN'"

util.summary "l7/dns"
