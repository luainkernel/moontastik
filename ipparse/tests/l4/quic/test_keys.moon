--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_keys.moon
-- Tests for QUIC v1 key derivation using RFC 9001 §A.1 test vectors

util = require "ipparse.lib.util"
{:test} = util
{:hkdf_extract, :hkdf_expand_label, :hex_to_bin} = require "ipparse.lib.hkdf"
{:derive_initial_secrets, :derive_keys, :INITIAL_SALT} = require "ipparse.l4.quic.v1.keys"

-- RFC 9001 §A.1 test vectors
-- DCID = 0x8394c8f03e515708
dcid = hex_to_bin "8394c8f03e515708"

-- Expected hex values from RFC 9001 §A.1
E_CLIENT_SECRET = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
E_SERVER_SECRET = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
E_CLIENT_KEY    = "1f369613dd76d5467730efcbe3b1a22d"
E_CLIENT_IV     = "fa044b2f42a3fd3b46fb255c"
E_CLIENT_HP     = "9f50449e04a0e810283a1e9933adedd2"
E_SERVER_KEY    = "cf3a5331653c364c88f0f379b6067e37"
E_SERVER_IV     = "0ac1493ca1905853b0bba03e"
E_SERVER_HP     = "c206b8d9b9f0f37644430b490eeaa314"

bin2hex = (s) ->
  s\gsub ".", (c) -> string.format "%02x", string.byte c

test "keys: INITIAL_SALT matches RFC 9001", ->
  expected_hex = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
  got_hex = bin2hex INITIAL_SALT
  assert got_hex == expected_hex, "INITIAL_SALT mismatch: #{got_hex}"

test "keys: derive_initial_secrets returns client and server", ->
  cs, ss = derive_initial_secrets dcid
  assert type(cs) == "string" and #cs == 32, "client_secret must be 32 bytes"
  assert type(ss) == "string" and #ss == 32, "server_secret must be 32 bytes"

test "keys: client_initial_secret matches RFC 9001 §A.1", ->
  cs, _ = derive_initial_secrets dcid
  assert bin2hex(cs) == E_CLIENT_SECRET, "client_secret mismatch:\ngot: #{bin2hex cs}"

test "keys: server_initial_secret matches RFC 9001 §A.1", ->
  _, ss = derive_initial_secrets dcid
  assert bin2hex(ss) == E_SERVER_SECRET, "server_secret mismatch:\ngot: #{bin2hex ss}"

test "keys: client quic key matches RFC 9001 §A.1", ->
  cs, _ = derive_initial_secrets dcid
  key, _, _ = derive_keys cs
  assert bin2hex(key) == E_CLIENT_KEY, "client key mismatch:\ngot: #{bin2hex key}"

test "keys: client quic iv matches RFC 9001 §A.1", ->
  cs, _ = derive_initial_secrets dcid
  _, iv, _ = derive_keys cs
  assert bin2hex(iv) == E_CLIENT_IV, "client iv mismatch:\ngot: #{bin2hex iv}"

test "keys: client hp key matches RFC 9001 §A.1", ->
  cs, _ = derive_initial_secrets dcid
  _, _, hp = derive_keys cs
  assert bin2hex(hp) == E_CLIENT_HP, "client hp mismatch:\ngot: #{bin2hex hp}"

test "keys: server quic key matches RFC 9001 §A.1", ->
  _, ss = derive_initial_secrets dcid
  key, _, _ = derive_keys ss
  assert bin2hex(key) == E_SERVER_KEY, "server key mismatch:\ngot: #{bin2hex key}"

test "keys: server quic iv matches RFC 9001 §A.1", ->
  _, ss = derive_initial_secrets dcid
  _, iv, _ = derive_keys ss
  assert bin2hex(iv) == E_SERVER_IV, "server iv mismatch:\ngot: #{bin2hex iv}"

test "keys: server hp key matches RFC 9001 §A.1", ->
  _, ss = derive_initial_secrets dcid
  _, _, hp = derive_keys ss
  assert bin2hex(hp) == E_SERVER_HP, "server hp mismatch:\ngot: #{bin2hex hp}"

util.summary "keys"
