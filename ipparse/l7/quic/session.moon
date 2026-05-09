--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Stateful QUIC Initial session helper (on-wire datagrams only).
-- Consumes raw QUIC packet bytes (UDP payloads), decrypts Initial packets,
-- reassembles CRYPTO stream fragments, and extracts TLS SNI.
--
-- @module l7.quic.session

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
quic_mod  = require "ipparse.l4.quic"
prot_mod  = require "ipparse.l4.quic.v1.protection"
ch_mod    = require "ipparse.l7.tls.handshake.client_hello"
ext_mod   = require "ipparse.l7.tls.handshake.extension"
sn_mod    = require "ipparse.l7.tls.handshake.extension.server_name"
{:iter_frames} = require "ipparse.l4.quic.frames"
keys_mod = nil

load_keys_module = ->
  return keys_mod if keys_mod
  mod_name = "ipparse.l4.quic.v1.keys"
  package.loaded[mod_name] = nil
  ok, mod_or_err = pcall require, mod_name
  return nil, "quic_keys_load_failed: #{mod_or_err}" unless ok and mod_or_err
  keys_mod = mod_or_err
  keys_mod

derive_quic_keyset = (keys, dcid) ->
  client_secret, server_secret = keys.derive_initial_secrets dcid
  ckey, civ, chp = keys.derive_keys client_secret
  skey, siv, shp = keys.derive_keys server_secret
  {
    :client_secret
    :server_secret
    client_keys: key: ckey, iv: civ, hp_key: chp
    server_keys: key: skey, iv: siv, hp_key: shp
  }

load_backend = ->
  errs = {}
  for mod in *{
    "ipparse.lib.crypto.backend.lunatik"
    "ipparse.lib.crypto.backend.ffi_wolfssl"
    "ipparse.lib.crypto.backend.ffi_mbedtls"
    "ipparse.lib.crypto.backend.ffi_openssl"
  }
    package.loaded[mod] = nil
    ok, backend = pcall require, mod
    return backend if ok and backend
    errs[#errs + 1] = "#{mod}: #{backend}"
  nil, "crypto backend not available (" .. table.concat(errs, " | ") .. ")"

reassemble_stream = (chunks) ->
  offsets = [off for off, _ in pairs chunks]
  return "" if #offsets == 0
  table.sort offsets

  out = {}
  expected = 0

  for off in *offsets
    chunk = chunks[off]
    clen = #chunk
    chunk_end = off + clen - 1
    continue if chunk_end < expected
    break if off > expected
    start_idx = expected > off and (expected - off + 1) or 1
    out[#out + 1] = chunk\sub start_idx
    expected = chunk_end + 1

  table.concat out

sni_from_tls = (tls_data) ->
  return nil if #tls_data < 4
  off = 1
  while off + 3 <= #tls_data
    msg_type = su "B", tls_data, off
    b_hi     = su "B",  tls_data, off + 1
    b_lo     = su ">H", tls_data, off + 2
    msg_len  = b_hi * 65536 + b_lo
    body_off = off + 4
    return nil if body_off + msg_len - 1 > #tls_data
    if msg_type == 0x01
      ch, _ = ch_mod.parse tls_data, body_off
      if ch and ch.extensions and #ch.extensions > 0
        ext_off = 1
        while ext_off <= #ch.extensions
          ext, next_off = ext_mod.parse ch.extensions, ext_off
          if ext.type == 0x0000
            sn, _ = sn_mod.parse ext.data, 1
            return sn.name if sn and sn.name and #sn.name > 0
          ext_off = next_off
    off = body_off + msg_len
  nil

session_mt = {}

append_crypto_frame = (self, frame) ->
  base = frame.offset or 0
  data = frame.data or ""
  prev = self.crypto_chunks[base]
  return true if prev and prev == data
  return nil, "conflicting CRYPTO frame at offset #{base}" if prev and prev != data

  data_end = base + #data - 1
  for off, chunk in pairs self.crypto_chunks
    chunk_end = off + #chunk - 1
    overlap_start = math.max base, off
    overlap_end = math.min data_end, chunk_end
    if overlap_start <= overlap_end
      for pos = overlap_start, overlap_end
        a = string.byte data, (pos - base + 1)
        b = string.byte chunk, (pos - off + 1)
        if a != b
          return nil, "conflicting CRYPTO byte at offset #{pos}"
  self.crypto_chunks[base] = data
  true

direction_from_header = (self, q, meta={}) ->
  return meta.direction if meta.direction
  return "client" unless self.initial_dcid
  if q.dst_connection_id == self.initial_dcid
    "client"
  elseif q.src_connection_id == self.initial_dcid
    "server"
  else
    "client"

ensure_keys = (self, q, direction) ->
  if not self.initial_dcid
    self.initial_dcid = q.dst_connection_id
  
  if direction == "client"
    if not self.client_keys
      keys, kerr = load_keys_module!
      return nil, kerr unless keys
      if not self.client_secret
        self.client_secret, self.server_secret = keys.derive_initial_secrets self.initial_dcid
      key, iv, hp = keys.derive_keys self.client_secret
      self.client_keys = {:key, :iv, hp_key: hp}
  else
    if not self.server_keys
      keys, kerr = load_keys_module!
      return nil, kerr unless keys
      if not self.server_secret
        self.client_secret, self.server_secret = keys.derive_initial_secrets self.initial_dcid
      key, iv, hp = keys.derive_keys self.server_secret
      self.server_keys = {:key, :iv, hp_key: hp}

  true, nil

decrypt_initial = (self, quic_packet, q, direction, keys_override=nil) ->
  keys = keys_override or (direction == "server" and self.server_keys or self.client_keys)
  expected = (self.pn_largest[direction] or -1) + 1
  if q.pkt_length and q.pn_off
    packet_end = (q.pn_off - 1) + q.pkt_length
    if packet_end > 0 and packet_end <= #quic_packet
      quic_packet = quic_packet\sub 1, packet_end
  pn_off = q.pn_off
  aad, pn, pn_len = prot_mod.unprotect_header quic_packet, pn_off, keys.hp_key, true, expected, self.backend
  payload_off = pn_off + pn_len
  plaintext, err = prot_mod.decrypt_payload quic_packet, payload_off, keys.key, keys.iv, pn, aad, self.backend
  return nil, err unless plaintext
  self.pn_largest[direction] = pn if pn > (self.pn_largest[direction] or -1)
  plaintext

bootstrap_initial = (self, quic_packet, q) ->
  keys, kerr = load_keys_module!
  return nil, kerr unless keys

  probes = {}
  seen = {}
  add_probe = (dcid, direction) ->
    return unless dcid and #dcid > 0
    key = "#{direction}:#{dcid}"
    return if seen[key]
    seen[key] = true
    probes[#probes + 1] = {:dcid, :direction}

  -- Most likely paths first.
  add_probe q.dst_connection_id, "client"
  add_probe q.src_connection_id, "server"
  add_probe q.dst_connection_id, "server"
  add_probe q.src_connection_id, "client"

  errs = {}
  for probe in *probes
    keyset = derive_quic_keyset keys, probe.dcid
    probe_keys = probe.direction == "server" and keyset.server_keys or keyset.client_keys
    plaintext, derr = decrypt_initial self, quic_packet, q, probe.direction, probe_keys
    if plaintext
      self.initial_dcid = probe.dcid
      self.client_secret = keyset.client_secret
      self.server_secret = keyset.server_secret
      self.client_keys = keyset.client_keys
      self.server_keys = keyset.server_keys
      return plaintext
    errs[#errs + 1] = "#{probe.direction}/dcid_len=#{#probe.dcid}: #{derr}"

  nil, "decrypt failed: bootstrap could not determine initial direction/DCID (" .. table.concat(errs, " | ") .. ")"

session_mt.__index =
  --- Pushes one raw QUIC packet (UDP payload bytes) into the session.
  -- @tparam string quic_packet Binary QUIC packet bytes.
  -- @tparam[opt] table meta Optional metadata (e.g. `direction = "client"|"server"`).
  -- @treturn boolean True if packet processed.
  -- @treturn string|nil Error message on failure.
  push: (quic_packet, meta={}) =>
    q, _ = quic_mod.parse quic_packet, 1
    return nil, "not a QUIC packet" unless q
    return nil, "only QUIC long headers are supported" unless q.long_header
    return nil, "missing packet number offset" unless q.pn_off
    return nil, "only QUIC Initial is supported" unless q.pkt_type == 0x00

    plaintext = nil
    if not self.initial_dcid
      plaintext, err = bootstrap_initial self, quic_packet, q
      return nil, err unless plaintext
    else
      direction = direction_from_header self, q, meta
      ok, key_err = ensure_keys self, q, direction
      return nil, (key_err or "could not derive QUIC keys") unless ok

      plaintext, err = decrypt_initial self, quic_packet, q, direction
      return nil, "decrypt failed: #{err}" unless plaintext

    for f in iter_frames plaintext
      continue unless f and f.name == "CRYPTO" and f.data
      ok_append, append_err = append_crypto_frame self, f
      return nil, append_err unless ok_append

    self.last_plaintext = plaintext
    self.sni_dirty = true
    true

  --- Returns the currently extracted SNI, if available.
  -- @treturn string|nil
  sni: =>
    if @sni_dirty
      @cached_sni = sni_from_tls reassemble_stream @crypto_chunks
      @sni_dirty = false
    @cached_sni

  --- Returns currently reassembled contiguous TLS CRYPTO bytes.
  -- @treturn string
  crypto_stream: =>
    reassemble_stream @crypto_chunks

  --- Returns the latest decrypted QUIC plaintext.
  -- @treturn string|nil
  plaintext: =>
    @last_plaintext

--- Creates a new QUIC Initial session decoder.
-- @tparam[opt] table opts Optional configuration.
-- @treturn table Session object.
new = (opts={}) ->
  backend = opts.backend
  unless backend
    backend, err = load_backend!
    error err unless backend

  setmetatable {
    :backend
    initial_dcid: opts.initial_dcid
    client_secret: opts.client_secret
    server_secret: opts.server_secret
    client_keys: opts.client_keys
    server_keys: opts.server_keys
    pn_largest: client: -1, server: -1
    crypto_chunks: {}
    last_plaintext: nil
    cached_sni: nil
    sni_dirty: true
  }, session_mt

{:new}
