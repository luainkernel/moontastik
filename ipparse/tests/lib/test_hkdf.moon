--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_hkdf.moon
-- Tests for HKDF-SHA256 (RFC 5869 test vectors + QUIC v1 vectors from RFC 9001 §A.1)

util = require "ipparse.lib.util"
{:test} = util
{:hkdf, :hkdf_extract, :hkdf_expand, :hkdf_expand_label, :hex_to_bin} = require "ipparse.lib.hkdf"

-- RFC 5869 Test Case 1
test "hkdf: RFC 5869 test case 1", ->
  result = hkdf(
    hex_to_bin "000102030405060708090a0b0c"
    hex_to_bin "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    hex_to_bin "f0f1f2f3f4f5f6f7f8f9"
    42
  )
  expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  assert result == expected, "TC1 mismatch:\ngot: #{result}\nexp: #{expected}"

-- RFC 5869 Test Case 3 (no salt, no info)
test "hkdf: RFC 5869 test case 3 (no salt/info)", ->
  result = hkdf(
    ""
    hex_to_bin "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    ""
    42
  )
  expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
  assert result == expected, "TC3 mismatch"

-- RFC 9001 §A.1 — QUIC v1 Initial packet key derivation
-- DCID = 0x8394c8f03e515708
dcid_hex = "8394c8f03e515708"
quic_salt = hex_to_bin "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

test "hkdf: QUIC initial_secret (RFC 9001 §A.1)", ->
  init_secret = hkdf_extract quic_salt, hex_to_bin dcid_hex
  -- client_initial_secret
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  expected = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
  assert csecret == expected, "client_initial_secret mismatch:\ngot: #{csecret}\nexp: #{expected}"

test "hkdf: QUIC client quic key (RFC 9001 §A.1)", ->
  init_secret = hkdf_extract quic_salt, hex_to_bin dcid_hex
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  key = hkdf_expand_label hex_to_bin(csecret), "quic key", "", 16
  expected = "1f369613dd76d5467730efcbe3b1a22d"
  assert key == expected, "client quic key mismatch:\ngot: #{key}\nexp: #{expected}"

test "hkdf: QUIC client quic iv (RFC 9001 §A.1)", ->
  init_secret = hkdf_extract quic_salt, hex_to_bin dcid_hex
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  iv = hkdf_expand_label hex_to_bin(csecret), "quic iv", "", 12
  expected = "fa044b2f42a3fd3b46fb255c"
  assert iv == expected, "client quic iv mismatch:\ngot: #{iv}\nexp: #{expected}"

test "hkdf: QUIC client hp key (RFC 9001 §A.1)", ->
  init_secret = hkdf_extract quic_salt, hex_to_bin dcid_hex
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  hp = hkdf_expand_label hex_to_bin(csecret), "quic hp", "", 16
  expected = "9f50449e04a0e810283a1e9933adedd2"
  assert hp == expected, "client hp key mismatch:\ngot: #{hp}\nexp: #{expected}"

test "hkdf: QUIC server quic key (RFC 9001 §A.1)", ->
  init_secret = hkdf_extract quic_salt, hex_to_bin dcid_hex
  ssecret = hkdf_expand_label init_secret, "server in", "", 32
  key = hkdf_expand_label hex_to_bin(ssecret), "quic key", "", 16
  expected = "cf3a5331653c364c88f0f379b6067e37"
  assert key == expected, "server quic key mismatch:\ngot: #{key}\nexp: #{expected}"

util.summary "hkdf"
