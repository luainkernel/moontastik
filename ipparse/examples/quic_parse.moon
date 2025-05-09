#!/usr/bin/env moon

-- ipparse - Learn How to Parse QUIC SNI
-- =====================================
--
-- This tutorial demonstrates how to use the `ipparse` library to parse a raw network
-- packet, starting from the Ethernet layer (L2), through IP (L3) and UDP (L4),
-- up to the QUIC layer (L7) to extract the Server Name Indication (SNI)
-- from a ClientHello message embedded within a QUIC Initial packet.
--
-- The `ipparse` library provides object-oriented access to packet data.
-- This example anticipates a future API for QUIC parsing.
--
-- Prerequisites:
-- - `ipparse` library compiled and available in your LUA_PATH.
-- - Future `ipparse.l7.quic` module (API defined hypothetically here).

-- Setup: Require necessary modules
-- We'll need modules for each layer we're parsing, plus some utilities.
eth       = require "ipparse.l2.ethernet"
ip        = require "ipparse.l3.ip"
udp       = require "ipparse.l4.udp" -- For UDP Layer
quic      = require "ipparse.l7.quic" -- Hypothetical QUIC module
hs        = require "ipparse.l7.tls.handshake.init" -- For Handshake messages
ch_hello  = require "ipparse.l7.tls.handshake.client_hello" -- For ClientHello structure
sni       = require "ipparse.l7.tls.handshake.extension.server_name" -- For SNI extension
ipu       = require "ipparse.init" -- For hex2bin utility

-- Sample Packet Data (QUIC Initial with SNI)
-- This version includes conceptual header and payload protection.
-- IMPORTANT: This is a SIMULATION of protection for a static example.
-- Real QUIC involves actual cryptographic operations (AEAD, header protection ciphers)
-- and key derivation using HKDF. We will simply XOR with a predictable "keystream"
-- derived from the DCID for this example to illustrate the structure.
-- This is a hexadecimal string representing a simplified Ethernet frame containing
-- an IPv4 packet, a UDP datagram, and a QUIC Initial packet.
-- The QUIC Initial packet contains a CRYPTO frame with a TLS ClientHello
-- message including an SNI extension for "example.com".
-- Lengths, checksums, and some QUIC fields are illustrative.

-- TLS ClientHello (without TLS Record Layer, as embedded in QUIC)
-- This is the plaintext ClientHello that will be inside a CRYPTO frame.
-- Type=ClientHello (0x01), Length (variable), Version (0x0303 for TLS 1.2),
-- Random, SessionID Len, CipherSuites, CompressionMethods, Extensions.
-- SNI Extension: Type (0x0000), Length, ServerNameList Length,
-- NameType (host_name=0x00), Name Length, Name.
tls_ch_hex = "0100003E" .. -- TLS Handshake: Type=ClientHello, Len=62
             "0303" .. -- ClientHello: Ver=TLS1.2
             "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" .. -- ClientHello: Random (32 bytes)
             "00" .. -- ClientHello: SessionID Len (0)
             "0002c02b" .. -- ClientHello: CipherSuites Len (2), 1 Suite
             "0100" .. -- ClientHello: CompressionMethods Len (1), 1 Method (null)
             "0014" .. -- ClientHello: Extensions Len (20 bytes for SNI)
             "0000" ..   -- Extension: Type=server_name (0x0000)
             "0010" ..   -- Extension: Length=16 bytes (SNI data)
             "000e" ..     -- SNI Data: ServerNameList Length=14 bytes
             "00" ..       -- SNI Data: NameType=host_name (0x00)
             "000b" ..     -- SNI Data: Name Length=10 bytes ("example.com")
             "6578616d706c652e636f6d" -- SNI Data: Name="example.com"

-- QUIC CRYPTO Frame containing the TLS ClientHello
-- Type (0x06), Offset (0), Length (of tls_ch_hex)
crypto_frame_data_len = #tls_ch_hex / 2
-- For simplicity, assume crypto_frame_data_len fits in 2 bytes for varint encoding (0x4000 | len)
crypto_frame_len_hex = string.format "%04x", (0x4000 | crypto_frame_data_len)
quic_crypto_frame_hex = "060000" .. crypto_frame_len_hex .. tls_ch_hex

-- QUIC Packet Number (unprotected, 1 byte for this example, value 0)
packet_number_hex = "00"

-- QUIC Payload (Frames only, before protection)
quic_frames_hex = quic_crypto_frame_hex

-- Constants for QUIC v1 Initial Packet Protection
-- Salt for QUIC v1 Initial Packets (RFC 9001, Section 5.2)
initial_salt_v1_hex = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

-- Dummy DCID (Destination Connection ID) - used for key derivation
dcid_hex = "aaaaaaaaaaaaaaaa" -- 8 bytes

-- SIMULATED Key Derivation (Highly Simplified for Example)
-- In real QUIC, HKDF is used with the salt and DCID to derive client_initial_secret,
-- then further keys for header protection (hp_key) and payload protection (key, iv).
-- For this example, we'll use a very naive "keystream" derived from DCID.
-- Let's use the first 5 bytes of DCID as a repeating keystream for header protection.
-- Let's use the first 16 bytes of DCID as a repeating keystream for payload protection.
simulated_hp_keystream_hex = string.sub(dcid_hex, 1, 10) -- 5 bytes for 1-byte flags + up to 4-byte PN
simulated_pp_keystream_hex = dcid_hex .. dcid_hex -- Repeat to ensure enough length for payload

-- Helper function for XORing hex strings (for simulation)
xor_hex_strings = (hex_a, hex_b) ->
  bin_a = ipu.hex2bin hex_a
  bin_b = ipu.hex2bin hex_b
  result_bin = ""
  min_len = math.min #bin_a, #bin_b
  for i=1,min_len
    result_bin ..= string.char(string.byte(bin_a, i) ~ string.byte(bin_b, i))
  -- Append remaining part of the longer string if any (shouldn't happen if keystream is managed)
  if #bin_a > min_len then result_bin ..= string.sub(bin_a, min_len + 1)
  elseif #bin_b > min_len then result_bin ..= string.sub(bin_b, min_len + 1)
  ipu.bin2hex result_bin

-- QUIC Header (Long Header, Initial Packet)
-- First byte: Header Form (1), Fixed Bit (1), Type (Initial=00), Reserved(00) -> 11000000 -> 0xC0
-- Packet Number Length: 00 (meaning 1 byte PN)
-- So, first byte before protection is 0xC0.
first_byte_unprotected_hex = "c0"

-- Header Protection Simulation
-- Protect: first_byte_unprotected_hex and packet_number_hex
header_to_protect_hex = first_byte_unprotected_hex .. packet_number_hex
-- Ensure keystream is long enough for what's being protected (1 byte flags + 1 byte PN = 2 bytes)
hp_keystream_segment_hex = string.sub(simulated_hp_keystream_hex, 1, #header_to_protect_hex)
protected_header_segment_hex = xor_hex_strings header_to_protect_hex, hp_keystream_segment_hex

first_byte_protected_hex = string.sub(protected_header_segment_hex, 1, 2)
protected_packet_number_hex = string.sub(protected_header_segment_hex, 3)

-- QUIC Header (Long Header, Initial Packet)
-- Version (e.g., 0x00000001)
-- DCID Len (08) + DCID (8 bytes dummy)
-- SCID Len (08) + SCID (8 bytes dummy)
-- Token Len (00)
-- Length (of protected Packet Number + protected Frames + 16 byte auth tag)
quic_len_val = (#protected_packet_number_hex / 2) + (#quic_frames_hex / 2) + 16
quic_len_hex_varint = ""
if quic_len_val < 64
  quic_len_hex_varint = string.format "%02x", quic_len_val
elseif quic_len_val < 16384
  quic_len_hex_varint = string.format "%04x", (0x4000 | quic_len_val)
else -- Simplified: use 4 bytes if larger, though QUIC supports 8
  quic_len_hex_varint = string.format "%08x", (0x80000000 | quic_len_val)

quic_header_prefix_hex = first_byte_protected_hex .. "00000001" .. -- Protected Flags/Type/PNLen, Version
                  "08" .. dcid_hex .. -- DCID Len, DCID
                  "08bbbbbbbbbbbbbbbb" .. -- SCID Len, SCID
                  "00" .. -- Token Len
                  quic_len_hex_varint -- Length (VarInt)

-- Payload Protection Simulation
-- Protect: quic_frames_hex
-- The protected packet number is part of the header, not the AEAD input for payload.
pp_keystream_segment_hex = string.sub(simulated_pp_keystream_hex, 1, #quic_frames_hex)
protected_frames_hex = xor_hex_strings quic_frames_hex, pp_keystream_segment_hex

-- Dummy Authentication Tag (16 bytes)
auth_tag_hex = "00000000000000000000000000000000"

-- Construct the full QUIC packet
quic_packet_hex = quic_header_prefix_hex .. protected_packet_number_hex .. protected_frames_hex .. auth_tag_hex

-- UDP Header
udp_len_hex = string.format "%04x", 8 + (#quic_packet_hex / 2) -- UDP Hdr Len + QUIC Packet Len
udp_header_hex = "c00201bb" .. udp_len_hex .. "0000" -- SrcPort, DstPort (443), Length, Checksum (0)

-- IPv4 Header
ip_total_len = 20 + (#udp_header_hex / 2) + (#quic_packet_hex / 2) -- IP Hdr + UDP Hdr + QUIC Pkt
ip_total_len_hex = string.format "%04x", ip_total_len
ip_header_hex = "4500" .. ip_total_len_hex .. "1234000040110000c0a80002c0a80001" -- ..., Proto=UDP (0x11), ...

-- Ethernet Header
eth_header_hex = "000102030405060708090a0b0800" -- Dst, Src, Type=IPv4

pkt_hex_quic = eth_header_hex .. ip_header_hex .. udp_header_hex .. quic_packet_hex

-- Convert hex string to binary data for parsing
raw_data = ipu.hex2bin pkt_hex_quic

print "--- Parsing QUIC SNI from Raw Packet ---"

-- Step 1: Parse Layer 2 - Ethernet Frame
eth_frame, l3_offset = eth.parse raw_data

unless eth_frame
  print "Error: Failed to parse Ethernet frame."
  return

print "\n-- Layer 2: Ethernet --"
print "Destination MAC: #{eth.mac2s eth_frame.dst}"
print "Source MAC: #{eth.mac2s eth_frame.src}"
print "EtherType: 0x#{string.format "%04x", eth_frame.protocol} (#{eth.proto[eth_frame.protocol] or "Unknown"})"

assert eth_frame.protocol == eth.proto.IP4, "Expected IPv4 packet"

-- Step 2: Parse Layer 3 - IP Packet
ip_pkt, l4_offset = ip.parse raw_data, l3_offset, eth_frame.protocol

unless ip_pkt
  print "Error: Failed to parse IP packet."
  return

print "\n-- Layer 3: IP --"
print "Version: #{ip_pkt.version}"
print "Source IP: #{ip.ip2s ip_pkt.src}"
print "Destination IP: #{ip.ip2s ip_pkt.dst}"
print "Protocol: 0x#{string.format "%02x", ip_pkt.protocol} (#{ip.proto[ip_pkt.protocol] or "Unknown"})"

assert ip_pkt.protocol == ip.proto.UDP, "Expected UDP packet"

-- Step 3: Parse Layer 4 - UDP Datagram
udp_dgram, l7_offset = udp.parse raw_data, l4_offset

unless udp_dgram
  print "Error: Failed to parse UDP datagram."
  return

print "\n-- Layer 4: UDP --"
print "Source Port: #{udp_dgram.spt}"
print "Destination Port: #{udp_dgram.dpt}"
print "Length: #{udp_dgram.len}"

-- Step 4: Parse Layer 7 - QUIC
print "\n-- Layer 7: QUIC --"

-- Hypothetical: quic.parse(data, offset, options)
-- Options might include {is_client: true} or port numbers for context.
quic_pkt, _ = quic.parse raw_data, l7_offset, { is_client: true }

unless quic_pkt
  print "Error: Failed to parse QUIC packet."
  return

print "QUIC Header Form: #{quic_pkt.header_form}" -- e.g., LONG or SHORT
if quic_pkt.header_form == quic.header_forms.LONG
  print "QUIC Long Packet Type: #{quic.long_packet_types[quic_pkt.type] or "Unknown"} (#{string.format "%02x", quic_pkt.type})"
  print "QUIC Version: 0x#{string.format "%08x", quic_pkt.version}"
  print "QUIC DCID: #{ipu.bin2hex quic_pkt.dcid}"
  print "QUIC SCID: #{ipu.bin2hex quic_pkt.scid}"

-- SNI is in TLS ClientHello within a CRYPTO frame.
sni_host = nil
ch_obj_quic = nil

-- Hypothetical: quic_pkt.payload contains the raw frame data
-- This payload would be AFTER decryption and removal of auth tag.
-- The packet number would also have been recovered via header protection removal.
-- Hypothetical: quic.iter_frames(payload_data) iterates over frames
-- For simplicity, we assume the first CRYPTO frame has our ClientHello.
-- The quic.parse function should ideally return the decrypted frames directly,
-- or provide a method to access them.
-- Let's assume quic_pkt.frames is a table of decrypted frames.
for frame in *quic_pkt.frames -- Assuming .frames is an iterable list of frame objects
  if frame.type == quic.frame_types.CRYPTO
    print "  Found QUIC CRYPTO Frame, Offset: #{frame.offset}, Length: #{frame.len}"
    -- The CRYPTO frame data contains TLS handshake messages.
    -- First, parse the handshake message header (expecting ClientHello).
    -- The offset for hs.parse is 0 because frame.data is the start of the TLS message.
    hs_header_quic, ch_data_offset = hs.parse frame.data, 0

    unless hs_header_quic and hs_header_quic.type == hs.message_types.client_hello
      print "    Error: Not a ClientHello message in CRYPTO frame or failed to parse."
      continue -- to next frame

    print "    TLS Handshake Message Type: client_hello"
    print "    TLS Handshake Message Length: #{hs_header_quic.len}"

    -- Now parse the ClientHello structure itself.
    ch_obj_quic, _ = ch_hello.parse frame.data, ch_data_offset

    unless ch_obj_quic
      print "    Error: Failed to parse ClientHello structure from CRYPTO frame."
      continue -- to next frame

    print "    ClientHello Protocol Version: 0x#{string.format "%04x", ch_obj_quic.version}"
    print "    ClientHello Extensions Block Length (raw): #{#ch_obj_quic.extensions}"

    -- Iterate through extensions to find SNI
    for extension in hs.iter_extensions ch_obj_quic.extensions
      ext_name = hs.extensions[extension.type] or "Unknown"
      -- print "      Found Extension: Type 0x#{string.format "%04x", extension.type} (#{ext_name}), Data Length #{#extension.data}"

      if extension.type == hs.extensions.server_name -- 0x0000
        print "      > Found Server Name Indication (SNI) Extension"
        -- Assuming sni.parse returns the parsed list object or nil
        -- and the object has a .names list and .incomplete flag.
        sni_list_obj = sni.parse extension.data

        if sni_list_obj and sni_list_obj.names and #sni_list_obj.names > 0
          name_entry = sni_list_obj.names[1]
          if name_entry and name_entry.type == sni.name_types.HOST_NAME
            sni_host = name_entry.name
            print "        SNI Host Name: #{sni_host}"
          else
            print "        Warning: First SNI entry not of type host_name or not found."
          if sni_list_obj and sni_list_obj.incomplete -- Check sni_list_obj exists before accessing .incomplete
            print "        Warning: SNI ServerNameList parsing was incomplete."
        else
          print "        Error: Failed to parse SNI data or no names found."
        break -- Found SNI in this ClientHello

    if sni_host then break -- Found SNI, exit CRYPTO frame processing and outer frame loop

print "\n--- End of QUIC SNI Parsing Tutorial ---"

print "\n--- Running Assertions ---"

-- Layer 2 Assertions
assert eth_frame, "Ethernet frame should be parsed"
assert eth.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "L2 Dst MAC mismatch"
assert eth_frame.protocol == eth.proto.IP4, "L2 EtherType should be IP4"

-- Layer 3 Assertions
assert ip_pkt, "IP packet should be parsed"
assert ip_pkt.protocol == ip.proto.UDP, "L3 Protocol should be UDP"

-- Layer 4 Assertions
assert udp_dgram, "UDP datagram should be parsed"
assert udp_dgram.dpt == 443, "L4 UDP Destination Port should be 443"

-- Layer 7 QUIC Assertions (Hypothetical API)
assert quic_pkt, "QUIC packet should be parsed"
assert quic_pkt.header_form == quic.header_forms.LONG, "QUIC Header Form mismatch"
assert quic_pkt.type == quic.long_packet_types.INITIAL, "QUIC Packet Type mismatch"
assert quic_pkt.version == 0x00000001, "QUIC Version mismatch"

-- Layer 7 TLS ClientHello (within QUIC) Assertions
assert ch_obj_quic, "ClientHello object from QUIC should be parsed"
assert ch_obj_quic.version == 0x0303, "L7 ClientHello Protocol Version mismatch"
assert #ch_obj_quic.extensions == 20, "L7 ClientHello Extensions Block Length mismatch"
assert sni_host == "example.com", "L7 SNI Host Name mismatch"

print "All assertions passed successfully!"
