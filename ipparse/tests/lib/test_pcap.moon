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

util.summary "pcap"
