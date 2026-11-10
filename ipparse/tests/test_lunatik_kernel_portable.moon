--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/test_lunatik_kernel_portable.moon
-- Runs the parsing/packing test modules that are portable to the Lunatik
-- kernel runtime: no FFI, no file/pcap access, no simulated package.preload.
-- FFI-dependent modules are still listed where their FFI use is optional and
-- guarded by pcall; they then only exercise their pure-Lua assertions.

util = require "ipparse.lib.util"

mods = {
  "ipparse.tests.test_fun"
  "ipparse.tests.test_init"
  "ipparse.tests.l2.test_ethernet"
  "ipparse.tests.l3.test_checksum"
  "ipparse.tests.l3.test_ip4"
  "ipparse.tests.l3.test_ip6"
  "ipparse.tests.l3.test_ip"
  "ipparse.tests.l4.test_tcp"
  "ipparse.tests.l4.test_udp"
  "ipparse.tests.l4.test_tcp_stream"
  "ipparse.tests.l7.test_dns"
  "ipparse.tests.l7.tls.test_handshake"
  "ipparse.tests.test_malformed"
  "ipparse.tests.lib.test_hkdf"
  "ipparse.tests.lib.test_bit_compat"
  "ipparse.tests.lib.test_pack_compat"
  "ipparse.tests.l4.quic.test_varint"
  "ipparse.tests.l4.quic.test_header"
  "ipparse.tests.l4.quic.test_frames"
  "ipparse.tests.l4.quic.test_keys"
  "ipparse.tests.l4.quic.test_protection"
  "ipparse.tests.l4.quic.test_integration"
  "ipparse.tests.l7.quic.test_session"
}

total_pass, total_all = 0, 0
load_errors = 0
for mod in *mods
  ok, err = pcall require, mod
  if ok
    total_pass += util._last_pass
    total_all += util._last_total
  else
    load_errors += 1
    print "ERROR loading #{mod}: #{err}"

print "\n==> Kernel portable total: #{total_pass}/#{total_all}"
failed = total_pass != total_all or load_errors > 0
if failed
  print "FAIL kernel portable suite: #{load_errors} load error(s), #{total_pass}/#{total_all} passed"
  error "kernel portable suite failed"
