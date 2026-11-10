--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_pcap.moon
-- PCAPNG parsing tests on in-memory blocks (userspace only).

util = require "ipparse.lib.util"
{:test} = util
{:pack} = require "ipparse.lib.pack_compat"
pcap = require "ipparse.lib.pcap"

make_shb = ->
  pack "<I4I4I4I2I2I8I4", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, 0, 28

make_idb = ->
  pack "<I4I4I2I2I4I4", 1, 20, 1, 0, 65535, 20

make_epb = (ts_hi, ts_lo, payload) ->
  block_len = 28 + #payload + 4
  pack("<I4I4I4I4I4I4I4", 6, block_len, 0, ts_hi, ts_lo, #payload, #payload) ..
    payload .. pack("<I4", block_len)

test "pcap: valid pcapng yields one Ethernet packet", ->
  data = make_shb! .. make_idb! .. make_epb 0, 0, "\001\002\003\004"
  packets = pcap.parse_pcapng_data data
  assert #packets == 1, "packets: #{#packets}"
  assert packets[1].packet_data == "\001\002\003\004", "payload mismatch"
  assert packets[1].interface.linktype_name == "ETHERNET", "linktype: #{packets[1].interface.linktype_name}"

test "pcap: unknown block with zero length terminates", ->
  data = make_shb! .. pack("<I4I4", 0xDEADBEEF, 0) .. make_idb!
  packets = pcap.parse_pcapng_data data
  assert #packets == 0, "packets: #{#packets}"

test "pcap: EPB with captured_len beyond block is skipped", ->
  block_len = 36
  header = pack "<I4I4I4I4I4I4I4", 6, block_len, 0, 0, 0, 100, 100
  data = make_shb! .. make_idb! .. header .. "\001\002\003\004" .. pack("<I4", block_len)
  packets = pcap.parse_pcapng_data data
  assert #packets == 0, "packets: #{#packets}"

test "pcap: truncated block at end terminates", ->
  epb = make_epb 0, 0, "\001\002\003\004"
  data = make_shb! .. make_idb! .. epb\sub 1, 20
  packets = pcap.parse_pcapng_data data
  assert #packets == 0, "packets: #{#packets}"

test "pcap: 64-bit timestamp keeps high word", ->
  data = make_shb! .. make_idb! .. make_epb 1, 2, "\001\002\003\004"
  packets = pcap.parse_pcapng_data data
  assert #packets == 1, "packets: #{#packets}"
  assert packets[1].timestamp == 4294967298, "timestamp: #{packets[1].timestamp}"

-- Build a full Ethernet + IPv4 + UDP + QUIC frame for filter tests.
eth = require "ipparse.l2.ethernet"
ip4 = require "ipparse.l3.ip4"
udp = require "ipparse.l4.udp"

make_quic_frame = (quic_data, sport, dport, protocol) ->
  protocol = protocol or 17
  udp_pkt = udp.pack udp.new { spt: sport, dpt: dport, checksum: 0, data: quic_data }
  ip_pkt = ip4.pack ip4.new {
    src: "\010\000\000\001"
    dst: "\010\000\000\002"
    protocol: protocol
    data: udp_pkt
  }
  pack("c6 c6 >H", "\000\001\002\003\004\005", "\006\007\008\009\010\011", 0x0800) .. ip_pkt

make_quic_long = (byte1) ->
  pack ">B I4 s1 s1", byte1, 0x00000001, string.rep("\001", 8), ""

test "pcap: filter_quic_packets keeps QUIC on port 443", ->
  frame = make_quic_frame make_quic_long(0xB0), 12345, 443
  res = pcap.filter_quic_packets { { packet_data: frame, timestamp: 7 } }
  assert #res == 1, "expected 1 QUIC packet, got #{#res}"
  assert res[1].udp_dgram.dpt == 443, "destination port mismatch"
  assert res[1].quic_pkt.long_header == true, "expected a long header"
  assert res[1].timestamp == 7, "timestamp should be forwarded"
  assert res[1].packet_num == 1, "packet_num should be 1"

test "pcap: filter_quic_packets ignores non-QUIC ports", ->
  frame = make_quic_frame make_quic_long(0xB0), 12345, 9999
  res = pcap.filter_quic_packets { { packet_data: frame } }
  assert #res == 0, "expected no QUIC packet, got #{#res}"

test "pcap: filter_quic_packets ignores non-UDP traffic", ->
  frame = make_quic_frame make_quic_long(0xB0), 12345, 443, 6
  res = pcap.filter_quic_packets { { packet_data: frame } }
  assert #res == 0, "expected no QUIC packet, got #{#res}"

test "pcap: filter_quic_packets ignores too-short frames", ->
  res = pcap.filter_quic_packets { { packet_data: "\001\002" } }
  assert #res == 0, "expected no QUIC packet, got #{#res}"

test "pcap: parse_pcapng reads a real temporary file", ->
  data = make_shb! .. make_idb! .. make_epb 0, 0, "\001\002\003\004"
  fname = os.tmpname!
  f = io.open fname, "wb"
  f\write data
  f\close!
  ok, packets = pcall pcap.parse_pcapng, fname
  os.remove fname
  assert ok, "parse_pcapng raised: #{packets}"
  assert #packets == 1, "expected 1 packet, got #{#packets}"
  assert packets[1].packet_data == "\001\002\003\004", "payload mismatch"

test "pcap: parse_pcapng raises on a missing file", ->
  ok, err = pcall pcap.parse_pcapng, "/nonexistent/definitely-missing.pcapng"
  assert not ok, "expected an error for a missing file"
  assert tostring(err)\find("Could not open", 1, true), "error should mention 'Could not open', got #{err}"

test "pcap: parse_pcapng_data logs when verbose", ->
  data = make_shb! .. make_idb! .. make_epb 0, 0, "\001\002\003\004"
  original_print = _G.print
  lines = { }
  _G.print = (msg) -> lines[#lines + 1] = msg
  pcap.verbose = true
  ok, packets = pcall pcap.parse_pcapng_data, data
  pcap.verbose = false
  _G.print = original_print
  assert ok, "parse_pcapng_data raised: #{packets}"
  assert #packets == 1, "expected 1 packet, got #{#packets}"
  assert #lines > 0, "expected verbose log lines"

make_shb_be = ->
  pack ">I4I4I4I2I2I8I4", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, 0, 28

make_idb_be = ->
  pack ">I4I4I2I2I4I4", 1, 20, 1, 0, 65535, 20

make_epb_be = (payload) ->
  block_len = 28 + #payload + 4
  pack(">I4I4I4I4I4I4I4", 6, block_len, 0, 0, 0, #payload, #payload) ..
    payload .. pack(">I4", block_len)

test "pcap: big-endian pcapng parses", ->
  data = make_shb_be! .. make_idb_be! .. make_epb_be "\001\002\003\004"
  packets = pcap.parse_pcapng_data data
  assert #packets == 1, "expected 1 packet, got #{#packets}"
  assert packets[1].packet_data == "\001\002\003\004", "payload mismatch"
  assert packets[1].endian == ">", "expected big-endian block"

test "pcap: parse_quic_from_pcapng finds a QUIC packet in a file", ->
  frame = make_quic_frame make_quic_long(0xB0), 12345, 443
  pad = (4 - (#frame % 4)) % 4
  frame = frame .. string.rep "\000", pad
  data = make_shb! .. make_idb! .. make_epb 0, 0, frame
  fname = os.tmpname!
  f = io.open fname, "wb"
  f\write data
  f\close!
  ok, res = pcall pcap.parse_quic_from_pcapng, fname
  os.remove fname
  assert ok, "parse_quic_from_pcapng raised: #{res}"
  assert #res == 1, "expected 1 QUIC packet, got #{#res}"
  assert res[1].udp_dgram.dpt == 443, "destination port mismatch"

util.summary "pcap"
