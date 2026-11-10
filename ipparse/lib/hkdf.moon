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

hmac_hex = (key, msg) -> bin_to_hex hmac_bin key, msg
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
  i, total, t, parts = 1, 0, "", {}
  while total < len
    t = hmac_hex prk, hex_to_bin(t) .. info .. char(i)
    parts[i] = t
    total += #t
    i += 1
  sub table.concat(parts), 1, len


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


:hkdf, :hkdf_extract, :hkdf_expand, :hkdf_expand_label, :hex_to_bin
