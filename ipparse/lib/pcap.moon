--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- PCAP/PCAPNG File Parsing Module
-- This module provides utilities for parsing PCAP and PCAPNG files to extract network packets.
-- It supports both the original PCAP format and the newer PCAPNG format.
--
-- ### Features
-- - Parse PCAPNG Section Header Blocks (SHB)
-- - Parse Interface Description Blocks (IDB)
-- - Parse Enhanced Packet Blocks (EPB)
-- - Extract raw packet data with timestamps
-- - Support for different link layer types (Ethernet, Raw IP)
--
-- ### PCAPNG Block Structure
-- ```
-- Block {
--   block_type (32): Type of block (SHB=0x0A0D0D0A, IDB=0x00000001, EPB=0x00000006)
--   block_total_length (32): Total length of block including headers
--   block_data (variable): Block-specific data
--   block_total_length (32): Repeated at end for validation
-- }
-- ```
--
-- References:
-- - RFC 2838: Pcap File Format
-- - PCAPNG Specification: https://github.com/pcapng/pcapng
--
-- @module lib.pcap

{:lshift} = require"ipparse.lib.bit_compat"

{:unpack, :pack} = require "ipparse.lib.pack_compat"
su = unpack
sp = pack
:bin2hex, :hex2bin, :need_bytes = require "ipparse.init"

--- PCAPNG Block Types
-- Mapping of block type codes to their names
block_types = {
  [0x0A0D0D0A]: "SHB"    -- Section Header Block
  [0x00000001]: "IDB"    -- Interface Description Block
  [0x00000006]: "EPB"    -- Enhanced Packet Block
  [0x00000002]: "PB"     -- Packet Block (deprecated)
  [0x00000003]: "SPB"    -- Simple Packet Block
  [0x00000004]: "NRB"    -- Name Resolution Block
  [0x00000005]: "ISB"    -- Interface Statistics Block
}

--- Link Layer Types (from pcap specification)
link_types = {
  [1]: "ETHERNET"        -- Ethernet (10Mb, 100Mb, 1000Mb, and up)
  [101]: "RAW_IP4"       -- Raw IP; the packet begins with an IPv4 header
  [228]: "RAW_IP6"       -- Raw IP; the packet begins with an IPv6 header
  [12]: "RAW_IP"         -- Raw IP; begins with IP header (version determines IPv4/IPv6)
}

-- Module-level verbosity flag: set `pcap.verbose = true` to trace parsing.
M = verbose: false
log = (msg) -> print msg if M.verbose

--- Parses a PCAPNG Section Header Block (SHB)
-- @tparam string data The binary data containing the SHB
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed SHB structure
-- @treturn number Next offset after the block
parse_shb = (data, offset) ->
  return nil, offset, "insufficient data for SHB header" unless need_bytes data, offset, 28

  -- The byte-order magic (offset +8) reads as 0x1A2B3C4D in the file's own
  -- byte order; anything else means the opposite endianness.
  endian = su(">I4", data, offset + 8) == 0x1A2B3C4D and ">" or "<"
  block_type = su "#{endian}I4", data, offset
  block_len = su "#{endian}I4", data, offset + 4
  byte_order_magic = su "#{endian}I4", data, offset + 8
  major_version = su "#{endian}I2", data, offset + 12
  minor_version = su "#{endian}I2", data, offset + 14
  section_length = su "#{endian}I8", data, offset + 16
  log "parse_shb: endian=#{endian}, block_type=#{block_type}, block_len=#{block_len}"

  shb = {
    :block_type, :block_len, :byte_order_magic, :major_version, :minor_version, :section_length, :endian
  }

  shb, offset + block_len

--- Parses a PCAPNG Interface Description Block (IDB)
-- @tparam string data The binary data containing the IDB
-- @tparam number offset Starting offset in the data
-- @tparam string endian Byte order (">" for big-endian, "<" for little-endian)
-- @treturn table Parsed IDB structure
-- @treturn number Next offset after the block
parse_idb = (data, offset, endian) ->
  return nil, offset, "insufficient data for IDB header" unless need_bytes data, offset, 16
  -- IDB format: block_type(4) + block_len(4) + linktype(2) + reserved(2) + snaplen(4) + options + block_len(4)
  block_type, block_len, linktype, reserved, snaplen = su "#{endian}I4I4I2I2I4", data, offset

  idb = {
    :block_type, :block_len, :linktype, :reserved, :snaplen, :endian
    linktype_name: link_types[linktype] or "UNKNOWN"
  }

  idb, offset + block_len

--- Parses a PCAPNG Enhanced Packet Block (EPB)
-- @tparam string data The binary data containing the EPB
-- @tparam number offset Starting offset in the data
-- @tparam string endian Byte order (">" for big-endian, "<" for little-endian)
-- @treturn table Parsed EPB structure with packet data
-- @treturn number Next offset after the block
parse_epb = (data, offset, endian) ->
  return nil, offset, "insufficient data for EPB header" unless need_bytes data, offset, 28
  -- EPB format: block_type(4) + block_len(4) + interface_id(4) + timestamp_high(4) + timestamp_low(4) + captured_len(4) + original_len(4) + packet_data + options + block_len(4)
  block_type, block_len, interface_id, timestamp_high, timestamp_low, captured_len, original_len = su "#{endian}I4I4I4I4I4I4I4", data, offset

  -- Extract packet data
  packet_start = offset + 28  -- After all the headers
  packet_data = data\sub packet_start, packet_start + captured_len - 1

  -- Calculate timestamp (microseconds since epoch, split into high/low 32-bit words)
  timestamp = lshift(timestamp_high, 32) + timestamp_low

  epb = {
    :block_type, :block_len, :interface_id, timestamp_hi: timestamp_high, timestamp_lo: timestamp_low, :timestamp
    :captured_len, :original_len, :packet_data, :endian
  }

  epb, offset + block_len

--- Parses a PCAPNG file and extracts all packets
-- @tparam string filename Path to the PCAPNG file
-- @treturn table Array of parsed packets with metadata
parse_pcapng = (filename) ->
  -- Read entire file into memory
  file = io.open filename, "rb"
  unless file
    error "Could not open file: #{filename}"

  data = file\read "*all"
  file\close!

  packets = {}
  all_blocks = {}
  interfaces = {}
  shb = nil
  offset = 1
  endian = ">"  -- Default big-endian, will be set by SHB

  while offset <= #data
    -- Read block type
    if offset + 8 > #data
      log "End of data at offset #{offset}"
      break

    -- Try reading with current endianness first
    block_type = su "#{endian}I4", data, offset
    block_name = block_types[block_type] or "UNKNOWN"
    log "Offset #{offset}: block_type=0x#{string.format "%08x", block_type} (#{block_name}), endian=#{endian}"

    -- If we don't recognize the block, and we haven't set endianness yet, try the other endianness
    if block_name == "UNKNOWN" and endian == ">"
      block_type = su "<I4", data, offset
      block_name = block_types[block_type] or "UNKNOWN"
      log "Trying little-endian: block_type=0x#{string.format "%08x", block_type} (#{block_name})"

    switch block_name
      when "SHB"
        shb_data, offset = parse_shb data, offset
        all_blocks[#all_blocks + 1] = {type: "SHB", data: shb_data}
        shb = shb_data
        endian = shb.endian
        log "Found Section Header Block - endian: #{endian}"

      when "IDB"
        idb, offset = parse_idb data, offset, endian
        all_blocks[#all_blocks + 1] = {type: "IDB", data: idb}
        interfaces[#interfaces + 1] = idb
        log "Found Interface Description Block - linktype: #{idb.linktype_name}"

      when "EPB"
        epb, offset = parse_epb data, offset, endian
        all_blocks[#all_blocks + 1] = {type: "EPB", data: epb}
        epb.interface = interfaces[epb.interface_id + 1]  -- IDs are 0-based
        packets[#packets + 1] = epb
        log "Found Enhanced Packet Block - packet #{#packets}, len: #{epb.captured_len}, timestamp: #{epb.timestamp}"

      else
        -- Store unknown block raw data
        if offset + 8 <= #data
          block_len = su "#{endian}I4", data, offset + 4
          raw_data = data\sub offset, offset + block_len - 1
          all_blocks[#all_blocks + 1] = {type: "UNKNOWN", :raw_data, :block_type}
          log "Found unknown block type: 0x#{string.format "%08x", block_type}, len: #{block_len} at offset #{offset}"
          offset += block_len
        else
          break

  log "Parsed #{#packets} packets from #{filename}"
  packets, all_blocks

--- Filters packets to find QUIC packets on standard ports
-- @tparam table packets Array of parsed packets
-- @treturn table Array of QUIC packets with parsed headers
filter_quic_packets = (packets) ->
  eth = require "ipparse.l2.ethernet"
  ip = require "ipparse.l3.ip"
  udp = require "ipparse.l4.udp"
  quic = require "ipparse.l4.quic"

  quic_packets = {}

  for i, packet in ipairs packets
    -- Parse Ethernet frame
    eth_frame, l3_offset = eth.parse packet.packet_data
    continue unless eth_frame

    -- Parse IP packet (IPv4 or IPv6)
    ip_pkt, l4_offset = ip.parse packet.packet_data, l3_offset, eth_frame.protocol
    continue unless ip_pkt and ip_pkt.protocol == ip.proto.UDP

    -- Parse UDP datagram
    udp_dgram, l7_offset = udp.parse packet.packet_data, l4_offset
    continue unless udp_dgram

    -- Filter for QUIC ports (443, 80, 8443, etc.)
    quic_ports = {[443]: true, [80]: true, [8443]: true, [4433]: true}
    is_quic = quic_ports[udp_dgram.spt] or quic_ports[udp_dgram.dpt]
    continue unless is_quic

    -- Parse QUIC header
    quic_pkt, _ = quic.parse packet.packet_data, l7_offset
    if quic_pkt
      quic_packet = {
        packet_num: i
        timestamp: packet.timestamp
        :eth_frame, :ip_pkt, :udp_dgram, :quic_pkt
        raw_data: packet.packet_data
        quic_offset: l7_offset
      }
      quic_packets[#quic_packets + 1] = quic_packet

      -- Print packet summary
      src_ip = ip.ip2s ip_pkt.src
      dst_ip = ip.ip2s ip_pkt.dst
      log "QUIC Packet #{i}: #{src_ip}:#{udp_dgram.spt} -> #{dst_ip}:#{udp_dgram.dpt}"

      if quic_pkt.long_header
        dcid = bin2hex quic_pkt.dst_connection_id
        scid = bin2hex quic_pkt.src_connection_id
        log "  Long Header - Version: 0x#{string.format "%08x", quic_pkt.version}, DCID: #{dcid}, SCID: #{scid}"
      else
        dcid = bin2hex quic_pkt.dst_connection_id
        log "  Short Header - DCID: #{dcid}"

  log "Found #{#quic_packets} QUIC packets"
  quic_packets

--- Packs a PCAPNG Section Header Block (SHB)
-- @tparam table shb The SHB structure to pack
-- @treturn string Packed SHB binary data
pack_shb = (shb) ->
  endian = shb.endian or "<"
  block_len = 28  -- SHB is always 28 bytes (no options)
  header = sp "#{endian}I4I4I4I2I2I8", shb.block_type, block_len, shb.byte_order_magic, shb.major_version, shb.minor_version, shb.section_length
  header .. sp "#{endian}I4", block_len

--- Packs a PCAPNG Interface Description Block (IDB)
-- @tparam table idb The IDB structure to pack
-- @treturn string Packed IDB binary data
pack_idb = (idb) ->
  endian = idb.endian or "<"
  block_len = 20  -- IDB is 20 bytes without options
  header = sp "#{endian}I4I4I2I2I4", idb.block_type, block_len, idb.linktype, idb.reserved, idb.snaplen
  header .. sp "#{endian}I4", block_len

--- Packs a PCAPNG Enhanced Packet Block (EPB)
-- @tparam table epb The EPB structure to pack
-- @treturn string Packed EPB binary data
pack_epb = (epb) ->
  endian = epb.endian or "<"
  -- Calculate block length: header(12) + packet_data + options + padding + block_len(4)
  packet_data = epb.packet_data
  packet_len = #packet_data
  -- Padding to 4-byte boundary
  padding_len = (4 - (packet_len % 4)) % 4
  padding = string.rep "\0", padding_len

  block_len = 12 + packet_len + padding_len + 4  -- header + data + padding + block_len
  header = sp "#{endian}I4I4I4I8I4", epb.block_type, block_len, epb.interface_id, epb.timestamp_hi, epb.timestamp_lo, epb.captured_len
  header .. packet_data .. padding .. sp "#{endian}I4", block_len

--- Writes a PCAPNG file from all blocks
-- @tparam string filename Output filename
-- @tparam table all_blocks Array of all blocks
write_pcapng = (filename, all_blocks) ->
  parts = {}

  for block in *all_blocks
    switch block.type
      when "SHB"
        parts[#parts + 1] = pack_shb block.data
      when "IDB"
        parts[#parts + 1] = pack_idb block.data
      when "EPB"
        parts[#parts + 1] = pack_epb block.data
      else
        parts[#parts + 1] = block.raw_data

  -- Combine all parts
  data = table.concat parts

  -- Write to file
  f = io.open filename, "wb"
  unless f
    return nil, "Cannot open file for writing: #{filename}"

  f\write data
  f\close!

  true

--- Main function to parse QUIC packets from a PCAPNG file
-- @tparam string filename Path to the PCAPNG file
-- @treturn table Array of QUIC packets with full parsing
parse_quic_from_pcapng = (filename="quic.pcapng") ->
  packets = parse_pcapng filename
  filter_quic_packets packets

M.parse_pcapng = parse_pcapng
M.parse_quic_from_pcapng = parse_quic_from_pcapng
M.filter_quic_packets = filter_quic_packets
M.block_types = block_types
M.link_types = link_types
M.pack_shb = pack_shb
M.pack_idb = pack_idb
M.pack_epb = pack_epb
M.write_pcapng = write_pcapng
M
