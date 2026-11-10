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

-- Simulated `crypto.shash` backend: `crypto.hkdf` is absent but
-- `crypto.shash` is present, so the module keeps hmac/sha256 nil and must
-- still be able to run hkdf_expand through the shash HMAC path.
sha_mod = nil
sha_is_hex = false
ok, m = pcall require, "ipparse.lib.sha"
if ok and m and m.hmac and m.sha256
  sha_mod = m
else
  ok, m = pcall require, "ipparse.lib.sha2"
  if ok and m and m.hmac and m.sha256
    sha_mod = m
    sha_is_hex = true

if sha_mod
  ref_hmac_bin = (key, msg) ->
    d = sha_mod.hmac sha_mod.sha256, key, msg
    if sha_is_hex then sha_mod.hex_to_bin d else d

  test "hkdf: shash-only backend expands RFC 5869 test case 1", ->
    loaded_before = {
      crypto: package.loaded["crypto"]
      crypto_hkdf: package.loaded["crypto.hkdf"]
      hkdf: package.loaded["ipparse.lib.hkdf"]
    }
    preload_before = {
      crypto: package.preload["crypto"]
      crypto_hkdf: package.preload["crypto.hkdf"]
    }
    run = ->
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = -> error "absent"
      package.loaded["crypto"] = {
        shash: (alg) ->
          assert alg == "hmac(sha256)", "unexpected shash algorithm: #{alg}"
          key = nil
          {
            setkey: (k) => key = k
            digest: (msg) => ref_hmac_bin key, msg
          }
      }
      package.loaded["ipparse.lib.hkdf"] = nil
      shash_hkdf = require "ipparse.lib.hkdf"
      result = shash_hkdf.hkdf(
        shash_hkdf.hex_to_bin "000102030405060708090a0b0c"
        shash_hkdf.hex_to_bin "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        shash_hkdf.hex_to_bin "f0f1f2f3f4f5f6f7f8f9"
        42
      )
      expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
      assert result == expected, "shash TC1 mismatch:\ngot: #{result}\nexp: #{expected}"
    ok, err = pcall run
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    error err unless ok

  test "hkdf: crypto.hkdf transform is created once", ->
    loaded_before = {
      crypto: package.loaded["crypto"]
      crypto_hkdf: package.loaded["crypto.hkdf"]
      hkdf: package.loaded["ipparse.lib.hkdf"]
    }
    preload_before = {
      crypto: package.preload["crypto"]
      crypto_hkdf: package.preload["crypto.hkdf"]
    }
    new_count = 0
    make_stub = ->
      new_count += 1
      obj = {}
      obj.extract = (salt, ikm) => ref_hmac_bin salt, ikm
      obj.expand = (prk, info, len) =>
        parts, t, i, total = {}, "", 1, 0
        while total < len
          t = ref_hmac_bin prk, t .. info .. string.char i
          parts[i] = t
          total += #t
          i += 1
        table.concat(parts)\sub 1, len
      obj.hkdf = (salt, ikm, info, len) =>
        prk = @extract salt, ikm
        @expand prk, info, len
      obj
    run = ->
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = -> { new: make_stub }
      package.loaded["ipparse.lib.hkdf"] = nil
      h = require "ipparse.lib.hkdf"
      prk = h.hkdf_extract h.hex_to_bin("000102030405060708090a0b0c"), h.hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      h.hkdf_expand prk, "", 32
      h.hkdf_expand_label prk, "label", "", 16
      assert new_count == 1, "crypto.hkdf.new should be called once, got #{new_count}"
    ok, err = pcall run
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    error err unless ok

  test "hkdf: shash transform is created once", ->
    loaded_before = {
      crypto: package.loaded["crypto"]
      crypto_hkdf: package.loaded["crypto.hkdf"]
      hkdf: package.loaded["ipparse.lib.hkdf"]
    }
    preload_before = {
      crypto: package.preload["crypto"]
      crypto_hkdf: package.preload["crypto.hkdf"]
    }
    shash_count = 0
    run = ->
      package.loaded["crypto.hkdf"] = nil
      package.preload["crypto.hkdf"] = -> error "absent"
      package.loaded["crypto"] = {
        shash: (alg) ->
          assert alg == "hmac(sha256)", "unexpected shash algorithm: #{alg}"
          shash_count += 1
          key = nil
          {
            setkey: (k) => key = k
            digest: (msg) => ref_hmac_bin key, msg
          }
      }
      package.loaded["ipparse.lib.hkdf"] = nil
      h = require "ipparse.lib.hkdf"
      prk = h.hkdf_extract h.hex_to_bin("000102030405060708090a0b0c"), h.hex_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      h.hkdf_expand prk, "", 32
      h.hkdf_expand_label prk, "label", "", 16
      assert shash_count == 1, "crypto.shash should be constructed once, got #{shash_count}"
    ok, err = pcall run
    package.loaded["crypto"] = loaded_before.crypto
    package.loaded["crypto.hkdf"] = loaded_before.crypto_hkdf
    package.loaded["ipparse.lib.hkdf"] = loaded_before.hkdf
    package.preload["crypto"] = preload_before.crypto
    package.preload["crypto.hkdf"] = preload_before.crypto_hkdf
    error err unless ok

-- RFC 5869 Test Case 2 (long inputs)
test "hkdf: RFC 5869 test case 2", ->
  result = hkdf(
    hex_to_bin "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    hex_to_bin "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    hex_to_bin "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    82
  )
  expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
  assert result == expected, "TC2 mismatch:\ngot: #{result}\nexp: #{expected}"

-- RFC 9001 §A.1 variant with DCID 0x0001020304050607
test "hkdf: QUIC test vector with DCID 0001020304050607", ->
  salt = hex_to_bin "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
  dcid = hex_to_bin "0001020304050607"
  init_secret = hkdf_extract salt, dcid
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  key = hkdf_expand_label hex_to_bin(csecret), "quic key", "", 16
  expected = "b14b918124fda5c8d79847602fa3520b"
  assert key == expected, "quic key mismatch:\ngot: #{key}\nexp: #{expected}"

util.summary "hkdf"
