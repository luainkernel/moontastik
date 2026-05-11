--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Layer 7 Module
-- Extracts application-layer information from decrypted QUIC frames.
-- Operates on already-decrypted QUIC payloads — no crypto dependency.
--
-- ### Usage
-- ```
-- frames_mod = require"ipparse.l4.quic.frames"
-- quic_l7 = require"ipparse.l7.quic"
-- sni = quic_l7.sni_from_plaintext(decrypted_payload)
-- ```
--
-- ### Notes
-- In QUIC, CRYPTO frames carry TLS handshake messages **directly**,
-- without the TLS record layer (RFC 9001 §4.1). Each CRYPTO frame has:
--   - name = "CRYPTO"
--   - offset: byte offset in the TLS handshake stream
--   - data: raw TLS handshake bytes
--
-- References:
-- - RFC 9000: QUIC Transport Protocol
-- - RFC 9001: Using TLS to Secure QUIC
-- - RFC 8446: TLS 1.3
--
-- @module l7.quic

pack: sp, unpack: su = require"ipparse.lib.pack_compat"
frames_mod = require"ipparse.l4.quic.frames"
ch_mod     = require"ipparse.l7.tls.handshake.client_hello"
ext_mod    = require"ipparse.l7.tls.handshake.extension"
sn_mod     = require"ipparse.l7.tls.handshake.extension.server_name"

--- Reassembles TLS data from a list of QUIC CRYPTO frames.
-- Handles retransmissions/overlaps by rebuilding a byte map from CRYPTO offsets.
-- @tparam table frames List of parsed QUIC frame objects.
-- @treturn string Reassembled TLS handshake data (may be empty).
reassemble_crypto = (frames) ->
  crypto = [{offset: f.offset or 0, data: f.data} for f in *frames when f.name == "CRYPTO" and f.data]
  return "" if #crypto == 0
  table.sort crypto, (a, b) -> a.offset < b.offset

  bytes_by_pos = {}
  highest = -1

  for f in *crypto
    data = f.data
    base = f.offset
    for i = 1, #data
      pos = base + i - 1
      v = string.byte data, i
      prev = bytes_by_pos[pos]
      bytes_by_pos[pos] = v unless prev and prev != v
      highest = pos if pos > highest

  return "" if highest < 0

  out = {}
  for pos = 0, highest
    break unless bytes_by_pos[pos]
    out[#out + 1] = string.char bytes_by_pos[pos]

  table.concat out

--- Extracts the SNI hostname from raw TLS handshake data.
-- Parses TLS handshake messages: type (1 byte) + length (3 bytes BE) + body.
-- In QUIC there is no TLS record wrapper (RFC 9001 §4.1).
-- For ClientHello (type 0x01), iterates extensions for server_name (0x0000).
-- @tparam string tls_data Raw TLS handshake bytes.
-- @treturn string|nil SNI hostname, or nil if not found.
sni_from_tls = (tls_data) ->
  return nil if #tls_data < 4
  off = 1
  while off + 3 <= #tls_data
    msg_type = su "B", tls_data, off
    b_hi     = su "B",  tls_data, off + 1
    b_lo     = su ">H", tls_data, off + 2  -- returns (value, next_off); only value used
    msg_len  = b_hi * 65536 + b_lo
    body_off = off + 4
    return nil if body_off + msg_len - 1 > #tls_data
    if msg_type == 0x01  -- ClientHello
      ch, _ = ch_mod.parse tls_data, body_off
      if ch and ch.extensions and #ch.extensions > 0
        ext_off = 1
        while ext_off <= #ch.extensions
          ext, next_off = ext_mod.parse ch.extensions, ext_off
          if ext.type == 0x0000  -- server_name
            sn, _ = sn_mod.parse ext.data, 1
            return sn.name if sn and sn.name and #sn.name > 0
          ext_off = next_off
    off = body_off + msg_len
  nil

--- Extracts the SNI hostname from a list of QUIC CRYPTO frames.
-- @tparam table frames List of parsed QUIC frame objects.
-- @treturn string|nil SNI hostname, or nil if not found.
sni_from_frames = (frames) ->
  sni_from_tls reassemble_crypto frames

--- Extracts the SNI hostname from a decrypted QUIC packet plaintext.
-- Parses QUIC frames from the plaintext, then extracts the SNI.
-- @tparam string plaintext Decrypted QUIC payload (AEAD output).
-- @treturn string|nil SNI hostname, or nil if not found.
sni_from_plaintext = (plaintext) ->
  collected = {}
  for f in frames_mod.iter_frames plaintext
    collected[#collected + 1] = f
  sni_from_frames collected

Session = require "ipparse.l7.quic.session"

{:reassemble_crypto, :sni_from_tls, :sni_from_frames, :sni_from_plaintext, :Session}
