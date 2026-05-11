--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC v1 key derivation (RFC 9001).
--
-- Derives the initial secrets, packet protection keys, IVs, and header
-- protection keys for a QUIC v1 connection from the destination Connection ID.
--
-- Uses `ipparse.lib.hkdf` (HKDF-SHA256 via crypto.hkdf/crypto.shash/pure-Lua fallback).
--
-- ### RFC 9001 §5.2 — Initial Secrets
-- initial_secret = HKDF-Extract(QUIC_V1_SALT, client_dst_connection_id)
-- client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
-- server_secret  = HKDF-Expand-Label(initial_secret, "server in", "", 32)
--
-- ### RFC 9001 §5.1 — Packet Protection Keys
-- key  = HKDF-Expand-Label(secret, "quic key", "", 16)
-- iv   = HKDF-Expand-Label(secret, "quic iv",  "", 12)
-- hp   = HKDF-Expand-Label(secret, "quic hp",  "", 16)
--
-- @module l4.quic.v1.keys

load_hkdf = ->
  mod_name = "ipparse.lib.hkdf"
  cached = package.loaded[mod_name]
  if type(cached) == "table" and cached.hkdf_extract and cached.hkdf_expand_label and cached.hex_to_bin
    return cached
  package.loaded[mod_name] = nil
  ok, mod_or_err = pcall require, mod_name
  error "quic_hkdf_load_failed: #{mod_or_err}" unless ok and mod_or_err
  mod_or_err

{:hkdf_extract, :hkdf_expand_label, :hex_to_bin} = load_hkdf!

--- QUIC v1 initial salt (RFC 9001 §5.2)
INITIAL_SALT = hex_to_bin "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

--- Derives client and server initial secrets from a destination Connection ID.
-- @tparam string dcid  Binary destination Connection ID (variable length)
-- @treturn string client_secret  32-byte binary secret
-- @treturn string server_secret  32-byte binary secret
derive_initial_secrets = (dcid) ->
  initial_secret = hkdf_extract INITIAL_SALT, dcid
  -- hkdf_expand_label returns a hex string; convert to binary
  client_secret = hex_to_bin hkdf_expand_label initial_secret, "client in", "", 32
  server_secret = hex_to_bin hkdf_expand_label initial_secret, "server in", "", 32
  client_secret, server_secret

--- Derives packet protection keys from a per-direction secret.
-- @tparam string secret  32-byte binary secret (client or server)
-- @treturn string key  16-byte packet protection key
-- @treturn string iv   12-byte packet protection IV
-- @treturn string hp   16-byte header protection key
derive_keys = (secret) ->
  key = hex_to_bin hkdf_expand_label secret, "quic key", "", 16
  iv  = hex_to_bin hkdf_expand_label secret, "quic iv",  "", 12
  hp  = hex_to_bin hkdf_expand_label secret, "quic hp",  "", 16
  key, iv, hp

{:INITIAL_SALT, :derive_initial_secrets, :derive_keys}
