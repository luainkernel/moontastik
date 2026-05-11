#!/usr/bin/env moon

--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--


-- Parse a real QUIC packet with RFC 9001 decryption
-- Complete L2-L7 extraction from a .pcap or .pcapng file.

do
  script_path = (arg and arg[0]) or ""
  if script_path == "" and debug and debug.getinfo
    src = debug.getinfo(1, "S").source or ""
    script_path = src\sub 2 if src\sub(1, 1) == "@"

  script_dir = script_path\match("^(.*)/[^/]+$") or "."
  project_root = "#{script_dir}/.."
  module_root = "#{project_root}/.."
  package.path = table.concat {
    package.path
    "#{module_root}/?.lua"
    "#{module_root}/?/init.lua"
  }, ";"

  ok_ffi = pcall require, "ffi"
  unless ok_ffi
    package.preload.ffi = -> require "ipparse.lib.ffi_stub"

pack_compat = require "ipparse.lib.pack_compat"
pack_compat.inject!

util = require "ipparse.lib.util"
eth = require "ipparse.l2.ethernet"
ip = require "ipparse.l3.ip"
udp = require "ipparse.l4.udp"
quic_mod = require "ipparse.l4.quic"
quic_session = require "ipparse.l7.quic.session"
unpack: su = pack_compat

bin2hex = util.bin2hex

parse_pcap = (filename) ->
  file = io.open filename, "rb"
  error "Could not open file: #{filename}" unless file

  data = file\read "*all"
  file\close!

  error "Invalid PCAP file (too short): #{filename}" if #data < 24

  magic_be = su ">I4", data, 1
  magic_le = su "<I4", data, 1

  endian = nil
  ts_div = 1e6

  if magic_be == 0xa1b2c3d4
    endian = ">"
  elseif magic_le == 0xa1b2c3d4
    endian = "<"
  elseif magic_be == 0xa1b23c4d
    endian = ">"
    ts_div = 1e9
  elseif magic_le == 0xa1b23c4d
    endian = "<"
    ts_div = 1e9
  else
    error "Unsupported PCAP magic: 0x#{string.format "%08x", magic_be}"

  packets = {}
  offset = 25
  while offset + 15 <= #data
    ts_sec, ts_frac, incl_len, orig_len = su "#{endian}I4I4I4I4", data, offset
    offset += 16
    break if incl_len < 0 or offset + incl_len - 1 > #data

    packet_data = data\sub offset, offset + incl_len - 1
    offset += incl_len

    packets[#packets + 1] = {
      timestamp: ts_sec + (ts_frac / ts_div)
      captured_len: incl_len
      original_len: orig_len
      :packet_data
    }

  packets

parse_pcapng = (filename) ->
  file = io.open filename, "rb"
  error "Could not open file: #{filename}" unless file

  data = file\read "*all"
  file\close!

  packets = {}
  interfaces = {}
  offset = 1
  endian = nil

  while offset + 11 <= #data
    block_type_le = su "<I4", data, offset
    block_type_be = su ">I4", data, offset
    block_type = block_type_le

    if block_type_le == 0x0A0D0D0A or block_type_be == 0x0A0D0D0A
      bom_le = su "<I4", data, offset + 8
      bom_be = su ">I4", data, offset + 8
      if bom_le == 0x1A2B3C4D
        endian = "<"
      elseif bom_be == 0x1A2B3C4D
        endian = ">"
      else
        error "Invalid SHB byte-order magic in #{filename}"
      block_type = 0x0A0D0D0A

    error "PCAPNG section header missing before offset #{offset}" unless endian

    block_len = su "#{endian}I4", data, offset + 4
    break if block_len < 12 or offset + block_len - 1 > #data

    if block_type == 0x00000001 -- IDB
      linktype = su "#{endian}I2", data, offset + 8
      interfaces[#interfaces + 1] = {:linktype}
    elseif block_type == 0x00000006 -- EPB
      interface_id, timestamp_high, timestamp_low, captured_len, original_len = su "#{endian}I4I4I4I4I4", data, offset + 8

      packet_start = offset + 28
      packet_end = packet_start + captured_len - 1
      if packet_end <= #data
        packets[#packets + 1] = {
          :interface_id, :timestamp_high, :timestamp_low, :captured_len, :original_len
          timestamp: timestamp_high * 2^32 + timestamp_low
          packet_data: data\sub(packet_start, packet_end)
          interface: interfaces[interface_id + 1]
        }

    offset += block_len

  packets

filter_quic_packets = (packets) ->
  quic_packets = {}
  quic_ports = {[443]: true, [80]: true, [8443]: true, [4433]: true}

  for i, packet in ipairs packets
    eth_frame, l3_offset = eth.parse packet.packet_data
    continue unless eth_frame

    ip_pkt, l4_offset = ip.parse packet.packet_data, l3_offset
    continue unless ip_pkt and ip_pkt.protocol == ip.proto.UDP

    udp_dgram, l7_offset = udp.parse packet.packet_data, l4_offset
    continue unless udp_dgram and (quic_ports[udp_dgram.spt] or quic_ports[udp_dgram.dpt])

    quic_pkt, _ = quic_mod.parse packet.packet_data, l7_offset
    continue unless quic_pkt

    quic_packets[#quic_packets + 1] = {
      packet_num: i
      timestamp: packet.timestamp
      :eth_frame, :ip_pkt, :udp_dgram, :quic_pkt
      raw_data: packet.packet_data
      quic_offset: l7_offset
    }

  quic_packets

load_quic_packets = (filename) ->
  if filename\lower!\match "%.pcapng$"
    return filter_quic_packets parse_pcapng filename
  if filename\lower!\match "%.pcap$"
    return filter_quic_packets parse_pcap filename

  ok_pcapng, pcapng_or_err = pcall ->
    filter_quic_packets parse_pcapng filename
  return pcapng_or_err if ok_pcapng

  ok_pcap, pcap_or_err = pcall ->
    filter_quic_packets parse_pcap filename
  return pcap_or_err if ok_pcap

  error "Could not parse capture as PCAPNG or PCAP: #{filename}"

pcap_file = arg and arg[1]
unless pcap_file
  print "Usage: #{arg and arg[0] or 'parse_real_quic.moon'} /path/to/capture.(pcap|pcapng)"
  os.exit 1

quic_packets = load_quic_packets pcap_file
if #quic_packets == 0
  print "ERROR: No QUIC packets found in #{pcap_file}"
  os.exit 1

pkt = nil
for candidate in *quic_packets
  q = candidate.quic_pkt
  if q and q.long_header and q.dst_connection_id and #q.dst_connection_id > 0
    pkt = candidate
    break

pkt or= quic_packets[1]

e = pkt.eth_frame
ip_pkt = pkt.ip_pkt
u = pkt.udp_dgram
q = pkt.quic_pkt
off3 = pkt.quic_offset
frame = pkt.raw_data

unless e and ip_pkt and u and q and off3 and frame
  print "ERROR: Failed to extract a fully parsed QUIC packet from #{pcap_file}"
  os.exit 1

unless q.pn_off
  print "ERROR: QUIC packet does not contain packet number offset (pn_off)"
  os.exit 1

pn_off_quic = q.pn_off - off3 + 1

print ""
print string.rep "=", 80
print "QUIC Packet Parser - #{pcap_file}"
print string.rep "=", 80
print ""

print "Selected packet: ##{pkt.packet_num or 1}"

print ""
print "Layer 2 (Ethernet):"
print "  src MAC: #{bin2hex e.src}"
print "  dst MAC: #{bin2hex e.dst}"

print ""
print "Layer 3 (IP):"
print "  src: #{ip.ip2s ip_pkt.src}"
print "  dst: #{ip.ip2s ip_pkt.dst}"

print ""
print "Layer 4 (UDP):"
print "  src port: #{u.spt}"
print "  dst port: #{u.dpt}"

print ""
print "Layer 7 (QUIC):"
print "  long header: #{tostring q.long_header}"
print string.format "  version: 0x%08x", q.version or 0
print "  DCID: #{q.dst_connection_id and bin2hex(q.dst_connection_id) or '<none>'}"
print "  packet length: #{q.pkt_length or #frame - off3 + 1} bytes"

print ""
print "RFC 9001 Decryption Pipeline:"

dcid = q.dst_connection_id
if dcid and #dcid > 0
  print "  ✓ Keys derived from DCID"

  ok_session, session_or_err = pcall quic_session.new
  unless ok_session and session_or_err
    print "  ⚠ Crypto backend not available"
  else
    session = session_or_err
    print "  ✓ Crypto backend loaded"

    pushed = 0
    decrypted = 0
    last_err = nil
    sni = nil

    for quic_candidate in *quic_packets
      qh = quic_candidate.quic_pkt
      continue unless qh and qh.long_header and qh.pkt_type == 0x00
      continue unless qh.dst_connection_id == dcid

      quic_bytes = quic_candidate.raw_data\sub quic_candidate.quic_offset
      ok_push, err_push = session\push quic_bytes
      pushed += 1
      if ok_push
        decrypted += 1
        sni = session\sni!
        if sni
          print "  ✓ Header protection removed"
          print "  ✓ Payload decrypted (stream reassembly across #{decrypted} Initial packets)"
          print "  ✓ SNI extracted: #{sni}"
          break
      else
        last_err = err_push

    unless sni
      if decrypted > 0
        print "  ✓ Header protection removed"
        print "  ✓ Payload decrypted"
        print "  ℹ SNI not found in payload"
      else
        print "  ✗ Decryption failed: #{last_err or 'no decryptable Initial packet found'}"
else
  print "  ✗ DCID not found"

print ""
print string.rep "=", 80
print "✓ Parsing complete"
print string.rep "=", 80
print ""
