#!/usr/bin/env moon

-- ipparse - Learn How to Parse DNS Queries
-- ========================================
--
-- This tutorial demonstrates how to use the `ipparse` library to parse a raw network
-- packet, starting from the Ethernet layer (L2), through IP (L3) and UDP (L4),
-- up to the DNS layer (L7) to extract information from a DNS query.
--
-- The `ipparse` library provides object-oriented access to packet data.
--
-- Prerequisites:
-- - `ipparse` library compiled and available in your LUA_PATH.

-- Setup: Require necessary modules
ethernet  = require "ipparse.l2.ethernet"
ip        = require "ipparse.l3.ip"
udp       = require "ipparse.l4.udp" -- For UDP Layer
dns       = require "ipparse.l7.dns" -- DNS module
ip_utils  = require "ipparse" -- For hex2bin utility

-- Sample Packet Data (DNS A Record Query for "example.com")
-- This is a hexadecimal string representing a simplified Ethernet frame containing
-- an IPv4 packet, a UDP datagram, and a DNS query.
-- Calculations for lengths:
-- DNS Question (17 bytes): "example.com" (13) + QTYPE (2) + QCLASS (2)
-- DNS Message (29 bytes): DNS Header (12) + DNS Question (17)
-- UDP Segment (37 bytes): UDP Header (8) + DNS Message (29)
-- IPv4 Packet (57 bytes): IPv4 Header (20) + UDP Segment (37)

dnsquestion = "000102030405060708090a0b0800" .. -- Ethernet: Dst MAC, Src MAC, EtherType IPv4
              "4500" .. string.format("%04x", 57) .. -- IPv4: V/IHL, ToS, Total Length (57 bytes)
              "abcd0000" ..                         -- IPv4: ID, Flags/FragOff
              "4011" ..                             -- IPv4: TTL (64), Protocol UDP (0x11)
              "0000" ..                             -- IPv4: Header Checksum (placeholder)
              "c0a80002" ..                         -- IPv4: Src IP (192.168.0.2)
              "c0a80001" ..                         -- IPv4: Dst IP (192.168.0.1)
              "c0030035" .. string.format("%04x", 37) .. -- UDP: Src Port (49155), Dst Port (53), Length (37 bytes)
              "0000" ..                             -- UDP: Checksum (placeholder)
              "1234" ..                             -- DNS: Transaction ID
              "0100" ..                             -- DNS: Flags (Standard query, RD=1)
              "0001" ..                             -- DNS: QDCOUNT (1 question)
              "0000" ..                             -- DNS: ANCOUNT
              "0000" ..                             -- DNS: NSCOUNT
              "0000" ..                             -- DNS: ARCOUNT
              "076578616d706c6503636f6d00" ..       -- DNS Question: Name ("example.com")
              "0001" ..                             -- DNS Question: QTYPE (A)
              "0001"                                -- DNS Question: QCLASS (IN)

-- Sample Packet Data (DNS A Record Answer for "example.com")
-- This is a simplified Ethernet frame containing an IPv4 packet, a UDP datagram,
-- and a DNS answer to the previous query.
-- Calculations for lengths:
-- DNS Question (17 bytes): "example.com" (13) + QTYPE (2) + QCLASS (2)
-- DNS Answer RR (16 bytes): Name Ptr (2) + Type A (2) + Class IN (2) + TTL (4) + RDLENGTH (2) + RDATA (IPv4 Addr, 4)
-- DNS Message (45 bytes): DNS Header (12) + DNS Question (17) + DNS Answer RR (16)
-- UDP Segment (53 bytes): UDP Header (8) + DNS Message (45)
-- IPv4 Packet (73 bytes): IPv4 Header (20) + UDP Segment (53)

dnsanswer = "060708090a0b0001020304050800" .. -- Ethernet: Dst MAC (was Src), Src MAC (was Dst), EtherType IPv4
            "4500" .. string.format("%04x", 74) .. -- IPv4: V/IHL, ToS, Total Length (should be 74 bytes: 20 IP header + 54 UDP datagram)
            "dcba0000" ..                         -- IPv4: ID (different from query)
            "4011" ..                             -- IPv4: TTL (64), Protocol UDP (0x11)
            "0000" ..                             -- IPv4: Header Checksum (placeholder - needs calculation for real use)
            "c0a80001" ..                         -- IPv4: Src IP (192.168.0.1 - resolver)
            "c0a80002" ..                         -- IPv4: Dst IP (192.168.0.2 - client)
            "0035c003" .. string.format("%04x", 54) .. -- UDP: Src Port (53), Dst Port (49155), Length (should be 54 bytes: 8 UDP header + 46 DNS message)
            "0000" ..                             -- UDP: Checksum (placeholder - needs calculation for real use)
            "1234" ..                             -- DNS: Transaction ID (same as query)
            "8180" ..                             -- DNS: Flags (Response, RD=1, RA=1, No error)
            "0001" ..                             -- DNS: QDCOUNT (1 question)
            "0001" ..                             -- DNS: ANCOUNT (1 answer)
            "0000" ..                             -- DNS: NSCOUNT
            "0000" ..                             -- DNS: ARCOUNT
            "076578616d706c6503636f6d00" ..       -- DNS Question: Name ("example.com")
            "0001" ..                             -- DNS Question: QTYPE (A)
            "0001" ..                             -- DNS Question: QCLASS (IN)
            "c00c" ..                             -- DNS Answer: Name (Pointer to "example.com" at offset 0x0c in DNS message)
            "0001" ..                             -- DNS Answer: TYPE (A)
            "0001" ..                             -- DNS Answer: CLASS (IN)
            "000000e1" ..                         -- DNS Answer: TTL (225 seconds)
            "0004" ..                             -- DNS Answer: RDLENGTH (4 bytes)
            "5db8d822"                            -- DNS Answer: RDATA (IP Address 93.184.216.34)

-- Convert hex string to binary data for parsing
raw_data_query = ip_utils.hex2bin dnsquestion
raw_data_answer = ip_utils.hex2bin dnsanswer

print "--- Parsing DNS Query from Raw Packet ---"

-- Step 1: Parse Layer 2 - Ethernet Frame
eth_frame, l3_offset = ethernet.parse raw_data_query

unless eth_frame
  print "Error: Failed to parse Ethernet frame."
  return

print "\n-- Layer 2: Ethernet --"
print "Destination MAC: #{ethernet.mac2s eth_frame.dst}"
print "Source MAC: #{ethernet.mac2s eth_frame.src}"
print "EtherType: 0x#{string.format "%04x", eth_frame.protocol} (#{ethernet.proto[eth_frame.protocol] or "Unknown"})"

assert eth_frame.protocol == ethernet.proto.IP4, "Expected IPv4 packet"

-- Step 2: Parse Layer 3 - IP Packet
ip_packet, l4_offset = ip.parse raw_data_query, l3_offset, eth_frame.protocol

unless ip_packet
  print "Error: Failed to parse IP packet."
  return

print "\n-- Layer 3: IP --"
print "Version: #{ip_packet.version}"
print "Source IP: #{ip.ip2s ip_packet.src}"
print "Destination IP: #{ip.ip2s ip_packet.dst}"
print "Protocol: 0x#{string.format "%02x", ip_packet.protocol} (#{ip.proto[ip_packet.protocol] or "Unknown"})"

assert ip_packet.protocol == ip.proto.UDP, "Expected UDP packet for DNS query"

-- Step 3: Parse Layer 4 - UDP Datagram
udp_dgram, l7_offset = udp.parse raw_data_query, l4_offset

unless udp_dgram
  print "Error: Failed to parse UDP datagram."
  return

print "\n-- Layer 4: UDP --"
print "Source Port: #{udp_dgram.spt}"
print "Destination Port: #{udp_dgram.dpt}"
print "Length: #{udp_dgram.len}"

assert udp_dgram.dpt == 53, "Expected UDP Destination Port 53 for DNS"

-- Step 4: Parse Layer 7 - DNS Message
print "\n-- Layer 7: DNS --"

-- dns.parse(data_string, l7_offset_in_data, is_tcp_boolean)
dns_msg_query, _ = dns.parse raw_data_query, l7_offset, false -- false because it's UDP

unless dns_msg_query
  print "Error: Failed to parse DNS message."
  return

print "DNS Transaction ID: 0x#{string.format "%04x", dns_msg_query.header.id}"
print "DNS Flags: 0x#{string.format "%04x", (dns_msg_query.header.qr_opcode_aa_tc_rd << 8) | dns_msg_query.header.ra_z_rcode}" -- Reconstruct raw flags
print "  Query/Response: #{dns_msg_query.header.qr and "Response" or "Query"}" -- Accessing parsed flag
print "  Recursion Desired: #{dns_msg_query.header.rd and "Yes" or "No"}" -- Accessing parsed flag
print "Number of Questions: #{dns_msg_query.header.qdcount}"
print "Number of Answers: #{dns_msg_query.header.ancount}"
-- Accessing questions from the parsed dns_msg_query object
if dns_msg_query.questions and #dns_msg_query.questions > 0
  question1_query = dns_msg_query.questions[1]
  print "  Question 1:"
  print "    Name: #{question1_query.name}" -- Parsed FQDN
  print "    Type: #{dns.types[question1_query.qtype] or "Unknown"} (0x#{string.format "%04x", question1_query.qtype})"
  print "    Class: #{dns.classes[question1_query.qclass] or "Unknown"} (0x#{string.format "%04x", question1_query.qclass})"
else
  print "  No questions found in DNS message."

print "\n--- End of DNS Query Parsing Tutorial ---"

print "\n--- Running Assertions for DNS Query ---"

-- Layer 2 Assertions
assert eth_frame, "Query L2: Ethernet frame should be parsed"
assert ethernet.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "Query L2: Dst MAC mismatch"
assert eth_frame.protocol == ethernet.proto.IP4, "Query L2: EtherType should be IP4"

-- Layer 3 Assertions
assert ip_packet, "Query L3: IP packet should be parsed"
assert ip_packet.protocol == ip.proto.UDP, "Query L3: Protocol should be UDP"

-- Layer 4 Assertions
assert udp_dgram, "Query L4: UDP datagram should be parsed"
assert udp_dgram.dpt == 53, "Query L4: UDP Destination Port should be 53"

-- Layer 7 DNS Assertions
assert dns_msg_query, "Query L7: DNS message should be parsed"
assert dns_msg_query.header.id == 0x1234, "Query L7: DNS Transaction ID mismatch"
assert dns_msg_query.header.qr == false, "Query L7: DNS QR flag should indicate Query"
assert dns_msg_query.header.rd == true, "Query L7: DNS RD flag should be true"
assert dns_msg_query.header.qdcount == 1, "Query L7: DNS QDCOUNT mismatch"
assert dns_msg_query.header.ancount == 0, "Query L7: DNS ANCOUNT mismatch"

assert dns_msg_query.questions and #dns_msg_query.questions == 1, "Query L7: DNS should have one question"
dns_q1_query = dns_msg_query.questions[1]
assert dns_q1_query, "Query L7: DNS Question 1 object should exist"
assert dns_q1_query.name == "example.com", "Query L7: DNS Question Name mismatch"
assert dns_q1_query.qtype == dns.types.A, "Query L7: DNS Question Type should be A"
assert dns_q1_query.qclass == dns.classes.IN, "Query L7: DNS Question Class should be IN"

print "All DNS Query assertions passed successfully!"

print "\n\n--- Parsing DNS Answer from Raw Packet ---"

-- Step 1: Parse Layer 2 - Ethernet Frame (Answer)
eth_frame_ans, l3_offset_ans = ethernet.parse raw_data_answer

unless eth_frame_ans
  print "Error: Failed to parse Ethernet frame for DNS answer."
  return

print "\n-- Layer 2: Ethernet (Answer) --"
print "Destination MAC: #{ethernet.mac2s eth_frame_ans.dst}"
print "Source MAC: #{ethernet.mac2s eth_frame_ans.src}"

-- Step 2: Parse Layer 3 - IP Packet (Answer)
ip_packet_ans, l4_offset_ans = ip.parse raw_data_answer, l3_offset_ans, eth_frame_ans.protocol

unless ip_packet_ans
  print "Error: Failed to parse IP packet for DNS answer."
  return

print "\n-- Layer 3: IP (Answer) --"
print "Source IP: #{ip.ip2s ip_packet_ans.src}"
print "Destination IP: #{ip.ip2s ip_packet_ans.dst}"

-- Step 3: Parse Layer 4 - UDP Datagram (Answer)
udp_dgram_ans, l7_offset_ans = udp.parse raw_data_answer, l4_offset_ans

unless udp_dgram_ans
  print "Error: Failed to parse UDP datagram for DNS answer."
  return

print "\n-- Layer 4: UDP (Answer) --"
print "Source Port: #{udp_dgram_ans.spt}"
print "Destination Port: #{udp_dgram_ans.dpt}"

-- Step 4: Parse Layer 7 - DNS Message (Answer)
print "\n-- Layer 7: DNS (Answer) --"
dns_msg_answer, _ = dns.parse raw_data_answer, l7_offset_ans, false -- false because it's UDP

assert dns_msg_answer, "Error: Failed to parse DNS answer message."

print "DNS Transaction ID: 0x#{string.format "%04x", dns_msg_answer.header.id}"
print "  Query/Response: #{dns_msg_answer.header.qr and "Response" or "Query"}"
print "  Authoritative Answer: #{dns_msg_answer.header.aa and "Yes" or "No"}"
print "  Recursion Available: #{dns_msg_answer.header.ra and "Yes" or "No"}"
print "Number of Questions: #{dns_msg_answer.header.qdcount}"
print "Number of Answers: #{dns_msg_answer.header.ancount}"

if dns_msg_answer.answers and #dns_msg_answer.answers > 0
  answer1 = dns_msg_answer.answers[1]
  print "  Answer 1:"
  print "    Name: #{answer1.name}" -- Should be "example.com" (possibly from pointer)
  print "    Type: #{dns.types[answer1.rtype] or "Unknown"} (0x#{string.format "%04x", answer1.rtype})"
  print "    Class: #{dns.classes[answer1.rclass] or "Unknown"} (0x#{string.format "%04x", answer1.rclass})"
  print "    TTL: #{answer1.ttl}"
  print "    RDLENGTH: #{#answer1.rdata}" -- Length of the rdata string
  -- For A record, rdata is the IP address in binary. Convert to string for display.
  if answer1.rtype == dns.types.A
    print "    RDATA (IP Address): #{ip.ip2s answer1.rdata}"
  else
    print "    RDATA (Hex): #{ip_utils.bin2hex answer1.rdata}"

print "\n--- End of DNS Answer Parsing Tutorial ---"

print "\n--- Running Assertions for DNS Answer ---"

-- Layer 7 DNS Answer Assertions
assert dns_msg_answer, "Answer L7: DNS message should be parsed"
assert dns_msg_answer.header.id == 0x1234, "Answer L7: DNS Transaction ID mismatch"
assert dns_msg_answer.header.qr == true, "Answer L7: DNS QR flag should indicate Response"
assert dns_msg_answer.header.ancount == 1, "Answer L7: DNS ANCOUNT mismatch"

assert dns_msg_answer.answers and #dns_msg_answer.answers == 1, "Answer L7: DNS should have one answer"
dns_ans1 = dns_msg_answer.answers[1]
assert dns_ans1, "Answer L7: DNS Answer 1 object should exist"
assert dns_ans1.name == "example.com", "Answer L7: DNS Answer Name mismatch"
assert dns_ans1.rtype == dns.types.A, "Answer L7: DNS Answer Type should be A"
assert dns_ans1.rclass == dns.classes.IN, "Answer L7: DNS Answer Class should be IN"
assert dns_ans1.ttl == 225, "Answer L7: DNS Answer TTL mismatch"
assert #dns_ans1.rdata == 4, "Answer L7: DNS Answer RDLENGTH mismatch for A record"
assert ip.ip2s(dns_ans1.rdata) == "93.184.216.34", "Answer L7: DNS Answer RDATA IP mismatch"

print "All DNS Answer assertions passed successfully!"
