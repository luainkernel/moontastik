#!/usr/bin/env moon

-- ipparse - Learn How to Parse TLS SNI
-- ====================================
--
-- This tutorial demonstrates how to use the `ipparse` library to parse a raw network
-- packet, starting from the Ethernet layer (L2), through IP (L3) and TCP (L4),
-- up to the TLS layer (L7) to extract the Server Name Indication (SNI)
-- from a ClientHello message.
--
-- The `ipparse` library provides object-oriented access to packet data,
-- simplifying the dissection of network protocols.
--
-- Prerequisites:
-- - `ipparse` library compiled and available in your LUA_PATH.
--   (Typically by running `make && sudo make install` in the ipparse directory,
--    or by ensuring the compiled .lua files are in your project's search path).

-- Setup: Require necessary modules
-- We'll need modules for each layer we're parsing, plus some utilities.
ethernet  = require "ipparse.l2.ethernet"
ip        = require "ipparse.l3.ip"
tcp       = require "ipparse.l4.tcp"
tls       = require "ipparse.l7.tls.init" -- For TLS Record Layer
handshake = require "ipparse.l7.tls.handshake.init" -- For Handshake messages
hello     = require "ipparse.l7.tls.handshake.client_hello" -- For ClientHello structure
sni       = require "ipparse.l7.tls.handshake.extension.server_name" -- For SNI extension
ip_utils  = require "ipparse.init" -- For hex2bin utility

local pkt_hex
if arg[1]
  with io.open arg[1]
    pkt_hex = \read"*a"
    \close!
  pkt_hex = table.concat [line for line in pkt_hex\gmatch"[^\n]+"]
  print pkt_hex
-- Sample Packet Data
-- This is a hexadecimal string representing a simplified Ethernet frame containing
-- an IPv4 packet, a TCP segment, and a TLS ClientHello message with an SNI extension
-- for "example.com". Checksums in IP and TCP headers are placeholders (0000).
pkt_hex or= "000102030405060708090a0b0800" .. -- Ethernet: Dst, Src, Type=IPv4
          "4500006F1234000040060000c0a80002c0a80001" .. -- IPv4: V/IHL, ToS, TotalLen=111, ID, Flags/Frag, TTL, Proto=TCP, Chksum, SrcIP, DstIP
          "c00101bb00000001000000005018200000000000" .. -- TCP: SrcPort, DstPort, Seq, Ack, HdrLen/Flags(PSH,ACK), Window, Chksum, UrgPtr
          "1603030042" .. -- TLS Record: Type=Handshake, Ver=TLS1.2, Len=66
          "0100003E" .. -- TLS Handshake: Type=ClientHello, Len=62
          "0303" .. -- ClientHello: Ver=TLS1.2
          "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" .. -- ClientHello: Random (32 bytes)
          "00" .. -- ClientHello: SessionID Len (0)
          "0002c02b" .. -- ClientHello: CipherSuites Len (2), 1 Suite (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
          "0100" .. -- ClientHello: CompressionMethods Len (1), 1 Method (null)
          "0014" .. -- ClientHello: Extensions Len (20 bytes for SNI)
          "0000" ..   -- Extension: Type=server_name (0x0000)
          "0010" ..   -- Extension: Length=16 bytes (SNI data)
          "000e" ..     -- SNI Data: ServerNameList Length=14 bytes
          "00" ..       -- SNI Data: NameType=host_name (0x00)
          "000b" ..     -- SNI Data: Name Length=10 bytes
          "6578616d706c652e636f6d" -- SNI Data: Name="example.com"

-- Convert hex string to binary data for parsing
raw_data = ip_utils.hex2bin pkt_hex

print "--- Parsing TLS SNI from Raw Packet ---"

-- Step 1: Parse Layer 2 - Ethernet Frame
-- `ethernet.parse(data_string, optional_offset)`
-- Returns: parsed_frame_object, offset_to_next_layer_payload
eth_frame, l3_offset = ethernet.parse raw_data

if not eth_frame
  print "Error: Failed to parse Ethernet frame."
  return -- Exit if L2 parsing fails

print "\n-- Layer 2: Ethernet --"
print "Destination MAC: #{ethernet.mac2s eth_frame.dst}"
print "Source MAC: #{ethernet.mac2s eth_frame.src}"
print "EtherType: 0x#{string.format "%04x", eth_frame.protocol} (#{ethernet.proto[eth_frame.protocol] or "Unknown"})"

-- We expect an IP packet. Check EtherType.
if eth_frame.protocol ~= ethernet.proto.IP4 and eth_frame.protocol ~= ethernet.proto.IP6
  print "Error: Not an IP packet. EtherType: 0x#{string.format "%04x", eth_frame.protocol}"
  return

-- Step 2: Parse Layer 3 - IP Packet
-- `ip.parse(data_string, offset_in_data_string, optional_ethertype)`
-- Returns: parsed_ip_object, offset_to_next_layer_payload
ip_packet, l4_offset = ip.parse(raw_data, l3_offset, eth_frame.protocol)

if not ip_packet
  print "Error: Failed to parse IP packet."
  return

print "\n-- Layer 3: IP --"
print "Version: #{ip_packet.version}"
print "Source IP: #{ip.ip2s ip_packet.src}"
print "Destination IP: #{ip.ip2s ip_packet.dst}"
print "Protocol: 0x#{string.format "%02x", ip_packet.protocol} (#{ip.proto[ip_packet.protocol] or "Unknown"})"

-- We expect a TCP segment. Check IP protocol.
if ip_packet.protocol ~= ip.proto.TCP
  print "Error: Not a TCP packet. IP Protocol: 0x#{string.format "%02x", ip_packet.protocol}"
  return

-- Step 3: Parse Layer 4 - TCP Segment
-- `tcp.parse(data_string, offset_in_data_string)`
-- Returns: parsed_tcp_object, offset_to_next_layer_payload (L7 data)
tcp_seg, l7_offset = tcp.parse(raw_data, l4_offset)

if not tcp_seg
  print "Error: Failed to parse TCP segment."
  return

print "\n-- Layer 4: TCP --"
print "Source Port: #{tcp_seg.spt}"
print "Destination Port: #{tcp_seg.dpt}"
print "Sequence Number: #{tcp_seg.seq_n}"
flags_list = {}
if tcp_seg.SYN then flags_list[#flags_list+1] = "SYN"
if tcp_seg.ACK then flags_list[#flags_list+1] = "ACK"
if tcp_seg.FIN then flags_list[#flags_list+1] = "FIN"
if tcp_seg.RST then flags_list[#flags_list+1] = "RST"
if tcp_seg.PSH then flags_list[#flags_list+1] = "PSH"
if tcp_seg.URG then flags_list[#flags_list+1] = "URG"
print "Flags: #{table.concat flags_list, " "} (0x#{string.format "%02x", tcp_seg.flags})"

-- The L7 payload (application data) starts at `l7_offset` in `raw_data`.
-- For HTTPS, this is where TLS data begins.

-- Step 4: Parse Layer 7 - TLS
print "\n-- Layer 7: TLS --"

-- 4a. Parse TLS Record Layer
-- `tls.parse(data_string, offset)`
-- Returns: parsed_tls_record_object, offset_to_tls_message_payload
tls_record, tls_offset = tls.parse(raw_data, l7_offset)

if not tls_record
  print "Error: Failed to parse TLS Record."
  return

print "TLS Record Type: 0x#{string.format "%02x", tls_record.type} (#{tls.record_types[tls_record.type] or "Unknown"})"
print "TLS Version in Record: 0x#{string.format "%02x%02x", tls_record.ver, tls_record.subver}" -- e.g., 0x0303 for TLS 1.2
print "TLS Record Payload Length: #{tls_record.len}"

-- We expect a Handshake message.
if tls_record.type ~= tls.record_types.handshake -- 0x16
  print "Error: Not a TLS Handshake record. Record Type: 0x#{string.format "%02x", tls_record.type}"
  return

-- The payload of the TLS Record (from `tls_offset` for `tls_record.len` bytes)
-- contains one or more TLS Handshake messages.

-- 4b. Parse TLS Handshake Message Header
-- `handshake.parse(data_string, offset)`
-- Returns: parsed_handshake_header_object, offset_to_handshake_message_data
-- A single TLS record can contain multiple handshake messages, but for ClientHello,
-- it's typically the first and often only one in its initial record.
hs_header, ch_offset = handshake.parse(raw_data, tls_offset)

if not hs_header
  print "Error: Failed to parse TLS Handshake message header."
  return

print "Handshake Message Type: 0x#{string.format "%02x", hs_header.type} (#{handshake.message_types[hs_header.type] or "Unknown"})"
print "Handshake Message Length: #{hs_header.len}"

-- We expect a ClientHello message.
if hs_header.type ~= handshake.message_types.client_hello -- 0x01
  print "Error: Not a ClientHello message. Handshake Type: 0x#{string.format "%02x", hs_header.type}"
  return

-- 4c. Parse ClientHello Message Structure
-- `hello.parse(data_string, offset)`
-- Returns: parsed_client_hello_object, offset_after_client_hello_fields
ch_obj, _ = hello.parse(raw_data, ch_offset)
-- The second return value (_ here) is the offset after all ClientHello fields, including extensions.

if not ch_obj
  print "Error: Failed to parse ClientHello message structure."
  return

print "ClientHello Protocol Version: 0x#{string.format "%04x", ch_obj.version}"
-- `ch_obj.extensions` contains the raw binary data of all extensions.
print "ClientHello Extensions Block Length (raw): #{#ch_obj.extensions}"

-- 4d. Iterate Through Extensions to Find Server Name Indication (SNI)
sni_host = nil
-- `handshake.iter_extensions(extensions_binary_blob)` returns an iterator.
-- Each `extension` object will have `type` (number) and `data` (string).
for extension in handshake.iter_extensions(ch_obj.extensions)
  ext_name = handshake.extensions[extension.type] or "Unknown"
  print "  Found Extension: Type 0x#{string.format "%04x", extension.type} (#{ext_name}), Data Length #{#extension.data}"

  if extension.type == handshake.extensions.server_name -- 0x0000
    print "  > Found Server Name Indication (SNI) Extension"
    -- Use `sni.parse` to parse the extension.data
    -- The `sni.parse` function handles the ServerNameList structure
    -- within the extension.data.
    sni_list = sni.parse extension.data

    if sni_list and sni_list.names and #sni_list.names > 0
      -- Typically, there's one ServerNameEntry in the list for SNI.
      -- We'll take the first one.
      name_entry = sni_list.names[1]
      if name_entry and name_entry.type == sni.name_types.HOST_NAME
        sni_host = name_entry.name
        print "    SNI Host Name: #{sni_host}"
      else
        print "    Warning: First SNI entry not of type host_name or not found."

      if sni_list.incomplete
        print "    Warning: SNI ServerNameList parsing was incomplete. #{err_msg or ''}"

    else
      print "    Error: Failed to parse SNI data using server_name_parser or no names found. #{err_msg or ''}"

    break -- Found and processed SNI, exit extension loop

os.exit! if arg[1]

print "\n--- End of SNI Parsing Tutorial ---"

print "\n--- Running Assertions ---"

-- Layer 2 Assertions
assert(eth_frame, "Ethernet frame should be parsed")
assert(ethernet.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "L2 Dst MAC mismatch")
assert(ethernet.mac2s(eth_frame.src) == "06:07:08:09:0a:0b", "L2 Src MAC mismatch")
assert(eth_frame.protocol == ethernet.proto.IP4, "L2 EtherType should be IP4")
assert(string.format("%04x", eth_frame.protocol) == "0800", "L2 EtherType hex mismatch")
assert(ethernet.proto[eth_frame.protocol] == "IP4", "L2 EtherType name mismatch")

-- Layer 3 Assertions
assert(ip_packet, "IP packet should be parsed")
assert(ip_packet.version == 4, "L3 IP Version mismatch")
assert(ip.ip2s(ip_packet.src) == "192.168.0.2", "L3 Source IP mismatch")
assert(ip.ip2s(ip_packet.dst) == "192.168.0.1", "L3 Destination IP mismatch")
assert(ip_packet.protocol == ip.proto.TCP, "L3 Protocol should be TCP")
assert(string.format("%02x", ip_packet.protocol) == "06", "L3 Protocol hex mismatch")
assert(ip.proto[ip_packet.protocol] == "TCP", "L3 Protocol name mismatch")

-- Layer 4 Assertions
assert(tcp_seg, "TCP segment should be parsed")
assert(tcp_seg.spt == 49153, "L4 TCP Source Port mismatch")
assert(tcp_seg.dpt == 443, "L4 TCP Destination Port mismatch")
assert(tcp_seg.seq_n == 1, "L4 TCP Sequence Number mismatch")
-- TCP Flags
assert(tcp_seg.ACK == true, "L4 TCP ACK flag should be true")
assert(tcp_seg.PSH == true, "L4 TCP PSH flag should be true")
assert(not tcp_seg.SYN, "L4 TCP SYN flag should be false")
assert(not tcp_seg.FIN, "L4 TCP FIN flag should be false")
assert(not tcp_seg.RST, "L4 TCP RST flag should be false")
assert(not tcp_seg.URG, "L4 TCP URG flag should be false")
flags_list_assert = {} -- Use a different name to avoid conflict if this script is run multiple times
if tcp_seg.SYN then flags_list_assert[#flags_list_assert + 1] = "SYN"
if tcp_seg.ACK then flags_list_assert[#flags_list_assert + 1] = "ACK"
if tcp_seg.FIN then flags_list_assert[#flags_list_assert + 1] = "FIN"
if tcp_seg.RST then flags_list_assert[#flags_list_assert + 1] = "RST"
if tcp_seg.PSH then flags_list_assert[#flags_list_assert + 1] = "PSH"
if tcp_seg.URG then flags_list_assert[#flags_list_assert + 1] = "URG"
assert(table.concat(flags_list_assert, " ") == "ACK PSH", "L4 TCP Flags string mismatch")
assert(tcp_seg.flags == 0x18, "L4 TCP Flags raw value mismatch")
assert(string.format("%02x", tcp_seg.flags) == "18", "L4 TCP Flags hex string mismatch")
-- Layer 7 TLS Assertions
assert(tls_record, "TLS Record should be parsed")
assert(tls_record.type == tls.record_types.handshake, "L7 TLS Record Type should be handshake")
assert(string.format("%02x", tls_record.type) == "16", "L7 TLS Record Type hex mismatch")
assert(tls.record_types[tls_record.type] == "handshake", "L7 TLS Record Type name mismatch")
assert(tls_record.ver == 0x03 and tls_record.subver == 0x03, "L7 TLS Version mismatch (expected 0x0303)")
assert(string.format("%02x%02x", tls_record.ver, tls_record.subver) == "0303", "L7 TLS Version string mismatch")
assert(tls_record.len == 66, "L7 TLS Record Payload Length mismatch")

assert(hs_header, "TLS Handshake message header should be parsed")
assert(hs_header.type == handshake.message_types.client_hello, "L7 Handshake Type should be client_hello")
assert(string.format("%02x", hs_header.type) == "01", "L7 Handshake Type hex mismatch")
assert(handshake.message_types[hs_header.type] == "client_hello", "L7 Handshake Type name mismatch")
assert(hs_header.len == 62, "L7 Handshake Message Length mismatch")

assert(ch_obj, "ClientHello object should be parsed")
assert(ch_obj.version == 0x0303, "L7 ClientHello Protocol Version mismatch")
assert(string.format("%04x", ch_obj.version) == "0303", "L7 ClientHello Protocol Version string mismatch")
assert(#ch_obj.extensions == 20, "L7 ClientHello Extensions Block Length mismatch")

assert(sni_host == "example.com", "L7 SNI Host Name mismatch")

print "All assertions passed successfully!"
