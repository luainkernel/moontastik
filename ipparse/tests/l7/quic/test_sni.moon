--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l7/quic/test_sni.moon
--
-- Tests for ipparse.l7.quic: reassemble_crypto, sni_from_tls, sni_from_plaintext.
-- All tests operate on pre-built plaintext / synthetic frames — no crypto required.

util    = require"ipparse.lib.util"
{:test} = util
pack: sp, unpack: su = require"ipparse.lib.pack_compat"
{:hex_to_bin} = require"ipparse.lib.hkdf"
quic_l7 = require "ipparse.l7.quic"
{:reassemble_crypto, :sni_from_tls, :sni_from_frames, :sni_from_plaintext} = quic_l7

-- ── Helpers ───────────────────────────────────────────────────────────────────

-- Build a TLS Handshake message as used in QUIC CRYPTO frames (no TLS record
-- layer, per RFC 9001 §4.1): type (1 byte) + length (3-byte big-endian) + body.
make_hs = (hs_type, body) ->
  n = #body
  sp(">BBH", hs_type, math.floor(n / 65536), n % 65536) .. body

-- Build a minimal ClientHello body ready to be wrapped in make_hs.
-- extensions_bin: raw concatenated extension bytes (already packed).
make_ch_body = (extensions_bin) ->
  client_random = string.rep "\x00", 32
  ciphers       = "\x13\x01"   -- TLS_AES_128_GCM_SHA256
  compressions  = "\x00"
  sp ">H c32 s1 s2 s1 s2", 0x0303, client_random, "", ciphers, compressions, extensions_bin

-- Build a server_name extension (ext type = 0x0000).
make_sni_ext = (hostname) ->
  entry    = sp ">B s2", 0x00, hostname   -- NameType=host_name + name
  sni_data = sp ">s2", entry              -- ServerNameList wrapper
  sp ">H s2", 0x0000, sni_data            -- Extension: type + data

-- Build an arbitrary extension with empty data.
make_ext = (ext_type) -> sp ">H s2", ext_type, ""

-- ── Group A : reassemble_crypto ───────────────────────────────────────────────

test "reassemble_crypto: empty list -> empty string", ->
  assert reassemble_crypto({}) == ""

test "reassemble_crypto: single CRYPTO frame", ->
  frames = {{name: "CRYPTO", offset: 0, data: "hello"}}
  assert reassemble_crypto(frames) == "hello"

test "reassemble_crypto: two frames in order", ->
  frames = {
    {name: "CRYPTO", offset: 0, data: "foo"}
    {name: "CRYPTO", offset: 3, data: "bar"}
  }
  assert reassemble_crypto(frames) == "foobar"

test "reassemble_crypto: two frames out of order", ->
  frames = {
    {name: "CRYPTO", offset: 5, data: "world"}
    {name: "CRYPTO", offset: 0, data: "hello"}
  }
  assert reassemble_crypto(frames) == "helloworld"

test "reassemble_crypto: non-CRYPTO frames are ignored", ->
  frames = {
    {name: "PADDING", offset: 0, data: "\x00\x00"}
    {name: "CRYPTO",  offset: 0, data: "data"}
    {name: "ACK",     offset: 0, data: "ack"}
  }
  assert reassemble_crypto(frames) == "data"

test "reassemble_crypto: retransmissions with same offsets are deduplicated", ->
  frames = {
    {name: "CRYPTO", offset: 0, data: "hello"}
    {name: "CRYPTO", offset: 0, data: "hello"}
    {name: "CRYPTO", offset: 5, data: "world"}
  }
  assert reassemble_crypto(frames) == "helloworld"

-- ── Group B : sni_from_tls ────────────────────────────────────────────────────

test "sni_from_tls: empty data -> nil", ->
  assert sni_from_tls("") == nil

test "sni_from_tls: ServerHello (type 2) -> nil", ->
  tls = make_hs 0x02, make_ch_body ""
  assert sni_from_tls(tls) == nil

test "sni_from_tls: ClientHello without extensions -> nil", ->
  tls = make_hs 0x01, make_ch_body ""
  assert sni_from_tls(tls) == nil

test "sni_from_tls: ClientHello with SNI -> hostname", ->
  tls = make_hs 0x01, make_ch_body make_sni_ext "test.example"
  assert sni_from_tls(tls) == "test.example",
    "expected 'test.example', got: #{tostring sni_from_tls tls}"

test "sni_from_tls: ClientHello with SNI not first extension -> correct SNI", ->
  ext_other = make_ext 0x002b   -- supported_versions placeholder
  tls = make_hs 0x01, make_ch_body (ext_other .. make_sni_ext "alt.example")
  assert sni_from_tls(tls) == "alt.example",
    "expected 'alt.example', got: #{tostring sni_from_tls tls}"

-- ── Group C : sni_from_plaintext (RFC 9001 §A.2 decrypted payload) ───────────
--
-- These are the first 245 bytes of the decrypted RFC 9001 §A.2 payload:
--   byte  1    : 0x06  CRYPTO frame type
--   byte  2    : 0x00  VarInt offset = 0
--   bytes 3-4  : 0x40 0xf1  VarInt length = 241
--   bytes 5-245: TLS ClientHello (type=0x01, len=237, SNI="example.com")
--
-- The plaintext is reproduced verbatim from an AES-128-GCM decryption of the
-- RFC 9001 §A.2 protected packet using the RFC-specified initial secrets.
PLAINTEXT_HEX = table.concat {
  "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c"
  "00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006"
  "001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa4"
  "7fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e040305"
  "0306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ff"
  "ff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"
}

test "sni_from_plaintext: RFC 9001 §A.2 payload -> 'example.com'", ->
  plaintext = hex_to_bin PLAINTEXT_HEX
  sni = sni_from_plaintext plaintext
  assert sni == "example.com",
    "expected 'example.com', got: #{tostring sni}"

util.summary "l7.quic.sni"
