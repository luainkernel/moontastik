--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Runs all test modules in order and reports per-module + grand total
util = require"ipparse.lib.util"
total_pass, total_all = 0, 0

is_luajit = type(jit) == "table"
lua_major, lua_minor = (_VERSION or "")\match "Lua (%d+)%.(%d+)"
lua_major = tonumber(lua_major) or 5
lua_minor = tonumber(lua_minor) or 1
is_pre53 = lua_major < 5 or (lua_major == 5 and lua_minor < 3)

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
  "ipparse.tests.lib.crypto.test_ffi_wolfssl"
  "ipparse.tests.lib.crypto.test_ffi_mbedtls"
  "ipparse.tests.l4.quic.test_varint"
  "ipparse.tests.l4.quic.test_header"
  "ipparse.tests.l4.quic.test_frames"
  "ipparse.tests.l4.quic.test_keys"
  "ipparse.tests.l4.quic.test_protection"
  "ipparse.tests.l4.quic.test_integration"
  "ipparse.tests.l7.quic.test_sni"
  "ipparse.tests.l7.quic.test_session"
  "ipparse.tests.l7.quic.test_google_capture_backends"
}

if is_luajit or is_pre53
  print "SKIP\tipparse.tests.lib.crypto.test_lunatik (requires Lua >= 5.3 non-LuaJIT runtime)"
else
  table.insert mods, 12, "ipparse.tests.lib.crypto.test_lunatik"

load_errors = 0
for mod in *mods
  ok, err = pcall require, mod
  if ok
    total_pass += util._last_pass
    total_all  += util._last_total
  else
    load_errors += 1
    print "ERROR loading #{mod}: #{err}"

print "\n==> Total: #{total_pass}/#{total_all}"
-- Propagate failures to the shell so CI notices (os.exit is absent in-kernel).
failed = total_pass != total_all or load_errors > 0
os.exit failed and 1 or 0 if os and os.exit
