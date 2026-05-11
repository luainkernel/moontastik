--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

is_hex_digest = (s) ->
  type(s) == "string" and #s == 64 and s\match("^[0-9a-fA-F]+$") != nil

bin_to_hex = (s) ->
  (s\gsub ".", (c) -> string.format "%02x", string.byte c)

hex_to_bin = (hex) ->
  (hex\gsub "..", (cc) -> string.char tonumber(cc, 16))

load_sha = ->
  ok, mod = pcall require, "ipparse.lib.sha"
  return mod if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin
  ok, mod = pcall require, "ipparse.lib.sha2"
  return mod if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin
  ok, mod = pcall require, "sha2"
  return mod if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin
  nil

load_crypto_hkdf = ->
  ok, mod = pcall require, "crypto.hkdf"
  return mod if ok and mod and mod.new
  nil

load_crypto_shash = ->
  ok, crypto = pcall require, "crypto"
  return nil unless ok and crypto and crypto.shash
  crypto.shash

crypto_hkdf = load_crypto_hkdf!
crypto_shash = nil
unless crypto_hkdf
  crypto_shash = load_crypto_shash!

sha = nil
hmac, sha256 = nil, nil
unless crypto_hkdf or crypto_shash
  sha = load_sha!
  error "no SHA backend available for HKDF" unless sha
  hmac, sha256 = sha.hmac, sha.sha256
  hex_to_bin = sha.hex_to_bin if sha.hex_to_bin

hmac_shash_bin = (key, msg) ->
  h = crypto_shash "hmac(sha256)"
  h\setkey key
  h\digest msg

hmac_bin = (key, msg) ->
  return hmac_shash_bin key, msg if crypto_shash
  error "hmac backend unavailable" unless hmac and sha256
  d = hmac sha256, key, msg
  if is_hex_digest d
    hex_to_bin d
  else
    d

hmac_hex = (key, msg) ->
  error "hmac backend unavailable" unless hmac and sha256
  d = hmac sha256, key, msg
  if is_hex_digest d
    d
  else
    bin_to_hex d
pack: sp, :char, :rep, :sub = require "ipparse.lib.pack_compat"


--- HKDF-Extract step.
-- Extracts a pseudorandom key (PRK) from the input keying material (IKM) and salt.
-- @tparam[opt=""] string salt Salt value (empty string becomes 64 zero bytes).
-- @tparam string ikm Input keying material.
-- @treturn string Pseudorandom key (PRK) as binary string.
hkdf_extract = (salt="", ikm) ->
  salt = rep "\0", 64 if salt == ""
  if crypto_hkdf
    return crypto_hkdf.new("sha256")\extract salt, ikm
  hmac_bin salt, ikm


--- HKDF-Expand step.
-- Expands the pseudorandom key (PRK) to produce output keying material.
-- @tparam string prk Pseudorandom key from HKDF-Extract.
-- @tparam[opt=""] string info Context and application specific information.
-- @tparam number len Length of output keying material in bytes.
-- @treturn string Output keying material (OKM) as hex string.
hkdf_expand = (prk, info="", len) ->
  if crypto_hkdf
    return bin_to_hex crypto_hkdf.new("sha256")\expand prk, info, len
  len *= 2
  i, okm, t = 1, "", ""
  while #okm < len
    t = hmac_hex prk, hex_to_bin(t) .. info .. char(i)
    okm ..= t
    i += 1
  sub okm, 1, len


--- Complete HKDF operation (Extract + Expand).
-- Derives output keying material from input keying material using HKDF.
-- @tparam string salt Salt value (empty string becomes 64 zero bytes).
-- @tparam string ikm Input keying material.
-- @tparam string info Context and application specific information.
-- @tparam number len Length of output keying material in bytes.
-- @treturn string Output keying material (OKM) as hex string.
hkdf = (salt, ikm, info, len) ->
  if crypto_hkdf
    return bin_to_hex crypto_hkdf.new("sha256")\hkdf salt, ikm, info, len
  hkdf_expand hkdf_extract(salt, ikm), info, len


hkdf_expand_label = (prk, label, context, len) ->
  hkdf_expand prk, sp(">Hs1s1", len, "tls13 "..label, context), len


--- Runs HKDF test vectors.
-- Validates the implementation against RFC 5869 test vectors and QUIC test vectors.
-- @treturn nil Prints "OK" if all tests pass.
test = ->
  assert hkdf(
    hex_to_bin"000102030405060708090a0b0c"
    hex_to_bin"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    hex_to_bin"f0f1f2f3f4f5f6f7f8f9"
    42
  ) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

  assert hkdf(
    hex_to_bin"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    hex_to_bin"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    hex_to_bin"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    82
  ) == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"

  assert hkdf(
    ""
    hex_to_bin"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    ""
    42
  ) == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

  init_secret = hkdf_extract hex_to_bin"38762cf7f55934b34d179ae6a4c80cadccbb7f0a", hex_to_bin"0001020304050607"
  csecret = hkdf_expand_label init_secret, "client in", "", 32
  assert hkdf_expand_label(hex_to_bin(csecret), "quic key", "", 16) == "b14b918124fda5c8d79847602fa3520b"
  print "OK"


if arg and arg[0] == debug.getinfo(1,"S").source\sub 2
  print "Running tests"
  test!

:hkdf, :hkdf_extract, :hkdf_expand, :hkdf_expand_label, :hex_to_bin, :test
