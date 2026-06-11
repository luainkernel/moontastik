--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l7/quic/test_google_capture_backends.moon
--
-- Real-capture end-to-end QUIC SNI extraction from quic_google.pcapng.
-- Runs the same L2 -> L7 pipeline against each crypto backend when available.

util = require "ipparse.lib.util"
{:test, :summary} = util

unpack: su = require "ipparse.lib.pack_compat"
eth_mod = require "ipparse.l2.ethernet"
ip_mod  = require "ipparse.l3.ip"
udp_mod = require "ipparse.l4.udp"
quic_mod = require "ipparse.l4.quic"
session_mod = require "ipparse.l7.quic.session"

bin2hex = (s) ->
  return s\gsub ".", (c) -> string.format "%02x", string.byte c

EXPECTED = {
  dst_mac: "f2198cc26bb3"
  src_mac: "f2e9008a2acc"
  src_ip:  "3ffa:e7fe:4375:16ed:e28f:4cff:fec8:91fa"
  dst_ip:  "2485:ec87:7655:20de::8b"  -- ip62s compresses zero runs (RFC 5952)
  udp_spt: 35336
  udp_dpt: 443
  sni: "google.com"
}

resolve_capture_path = ->
  candidates = {
    "ipparse/quic_google.pcapng"
    "quic_google.pcapng"
    "/lib/modules/lua/ipparse/quic_google.pcapng"
  }

  for path in *candidates
    f = io.open path, "rb"
    if f
      f\close!
      return path

  nil, "quic_google.pcapng not found (tried: #{table.concat candidates, ', '})"

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

    if block_type == 0x00000001
      linktype = su "#{endian}I2", data, offset + 8
      interfaces[#interfaces + 1] = {:linktype}
    elseif block_type == 0x00000006
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

load_flow = (capture_path) ->
  packets = parse_pcapng capture_path
  assert #packets > 0, "empty pcapng capture: #{capture_path}"

  first = nil
  initial_dcid = nil
  initial_datagrams = {}

  for packet in *packets
    e, l3_off = eth_mod.parse packet.packet_data, 1
    continue unless e

    ip_pkt, l4_off = ip_mod.parse packet.packet_data, l3_off
    continue unless ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP

    udp_dgram, l7_off = udp_mod.parse packet.packet_data, l4_off
    continue unless udp_dgram

    q, _ = quic_mod.parse packet.packet_data, l7_off
    continue unless q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0

    if not first
      first = {
        :e
        ip_pkt: ip_pkt
        udp_dgram: udp_dgram
        q: q
      }
      initial_dcid = q.dst_connection_id

    if q.dst_connection_id == initial_dcid
      initial_datagrams[#initial_datagrams + 1] = packet.packet_data\sub l7_off

  assert first ~= nil, "no QUIC Initial packet found in #{capture_path}"
  assert #initial_datagrams > 0, "no client Initial datagrams found for selected DCID"

  {
    :first
    :initial_datagrams
  }

capture_path, path_err = resolve_capture_path!
flow = nil
flow_err = nil
if capture_path
  ok, flow_or_err = pcall -> load_flow capture_path
  if ok
    flow = flow_or_err
  else
    flow_err = flow_or_err

run_backend = (label, backend_mod) ->
  ok_backend, backend_or_err = pcall require, backend_mod
  unless ok_backend and backend_or_err
    test "quic.google.capture: #{label} backend not available (skipped)", -> true
    return

  test "quic.google.capture: #{label} backend parses L2->SNI", ->
    assert capture_path ~= nil, path_err
    assert flow ~= nil, tostring(flow_err)

    f = flow.first
    assert bin2hex(f.e.dst) == EXPECTED.dst_mac, "dst mac mismatch: #{bin2hex f.e.dst}"
    assert bin2hex(f.e.src) == EXPECTED.src_mac, "src mac mismatch: #{bin2hex f.e.src}"
    assert ip_mod.ip2s(f.ip_pkt.src) == EXPECTED.src_ip, "src ip mismatch: #{ip_mod.ip2s f.ip_pkt.src}"
    assert ip_mod.ip2s(f.ip_pkt.dst) == EXPECTED.dst_ip, "dst ip mismatch: #{ip_mod.ip2s f.ip_pkt.dst}"
    assert f.udp_dgram.spt == EXPECTED.udp_spt, "udp source port mismatch: #{f.udp_dgram.spt}"
    assert f.udp_dgram.dpt == EXPECTED.udp_dpt, "udp destination port mismatch: #{f.udp_dgram.dpt}"
    assert f.q.long_header == true, "expected QUIC long header"
    assert f.q.pkt_type == 0x00, "expected QUIC Initial packet"

    sess = session_mod.new backend: backend_or_err
    for quic_packet in *flow.initial_datagrams
      ok_push, err_push = sess\push quic_packet
      assert ok_push, "#{label}: #{err_push}"
      break if sess\sni!

    assert sess\sni! == EXPECTED.sni, "expected SNI #{EXPECTED.sni}, got #{tostring sess\sni!}"

run_backend "lunatik", "ipparse.lib.crypto.backend.lunatik"
run_backend "wolfssl", "ipparse.lib.crypto.backend.ffi_wolfssl"
run_backend "mbedtls", "ipparse.lib.crypto.backend.ffi_mbedtls"
run_backend "openssl", "ipparse.lib.crypto.backend.ffi_openssl"

summary "l7.quic.google_capture_backends"
