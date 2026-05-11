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
  assert msg.answers[1].rdata == "\x5d\xb8\xd8\x22", "rdata mismatch"

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
util.summary "l7/dns"
