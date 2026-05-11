--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_integration.moon
--
-- End-to-end L2→L7 parsing test using the RFC 9001 §A.2 protected QUIC
-- client Initial packet wrapped in Ethernet + IPv4 + UDP headers.
--
-- Frame layout:
--   Ethernet  14 bytes  dst=aa:bb:cc:dd:ee:ff  src=11:22:33:44:55:66  type=0x0800
--   IPv4      20 bytes  src=192.168.1.1  dst=1.1.1.1  proto=17 TTL=64
--   UDP        8 bytes  spt=1234  dpt=443
--   QUIC    1200 bytes  RFC 9001 §A.2 protected client Initial
--
-- The crypto-dependent assertions (PN recovery, payload decryption, SNI) are
-- skipped when libcrypto is not available.

util    = require "ipparse.lib.util"
{:test} = util
{:hex_to_bin} = require "ipparse.lib.hkdf"

bin2hex = (s) -> s\gsub ".", (c) -> string.format "%02x", string.byte c

-- ── RFC 9001 §A.2 protected QUIC client Initial packet (1200 bytes) ─────────
QUIC_HEX = table.concat {
  "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
  "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
  "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
  "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
  "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
  "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
  "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
  "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
  "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
  "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
  "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
  "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
  "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
  "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
  "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
  "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
  "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
  "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
  "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
  "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
  "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
  "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
  "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
  "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
  "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
  "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
  "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
  "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
  "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
  "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
  "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
  "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
  "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
  "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
  "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
  "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
  "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
  "e221af44860018ab0856972e194cd934"
}

-- ── Build the full Ethernet + IPv4 + UDP + QUIC frame ────────────────────────
quic = hex_to_bin QUIC_HEX
assert #quic == 1200, "QUIC packet should be 1200 bytes, got #{#quic}"

sp = require("ipparse.lib.pack_compat").pack
checksum = require("ipparse.l3.lib").checksum

udp_len  = 8 + #quic
ip_total = 20 + udp_len

-- IPv4 header: placeholder checksum
ip_no_csum = sp(">BBHHHBBH", 0x45, 0, ip_total, 0x1234, 0x4000, 64, 17, 0) ..
  "\xc0\xa8\x01\x01" ..  -- src 192.168.1.1
  "\x01\x01\x01\x01"     -- dst 1.1.1.1
ip_csum   = checksum ip_no_csum
ip_hdr    = sp(">BBHHHBBH", 0x45, 0, ip_total, 0x1234, 0x4000, 64, 17, ip_csum) ..
  "\xc0\xa8\x01\x01" .. "\x01\x01\x01\x01"

-- Ethernet header
eth_hdr = "\xaa\xbb\xcc\xdd\xee\xff" ..  -- dst mac
          "\x11\x22\x33\x44\x55\x66" ..  -- src mac
          "\x08\x00"                      -- ethertype IPv4

-- UDP header
udp_hdr = sp ">HHHH", 1234, 443, udp_len, 0

frame = eth_hdr .. ip_hdr .. udp_hdr .. quic

-- ── Parse each layer once, share results across tests ───────────────────────
eth_mod  = require "ipparse.l2.ethernet"
ip_mod   = require "ipparse.l3.ip4"
udp_mod  = require "ipparse.l4.udp"
quic_mod = require "ipparse.l4.quic"

e,   off1 = eth_mod.parse  frame, 1
ip,  off2 = ip_mod.parse   frame, off1
u,   off3 = udp_mod.parse  frame, off2
q,   off4 = quic_mod.parse frame, off3

-- off3 = absolute offset of first QUIC byte in frame (1-based)
-- q.pn_off = absolute offset of (protected) PN field in frame
pn_off_quic = q.pn_off - off3 + 1   -- 1-based offset within the QUIC packet

-- ── Layer 2 ──────────────────────────────────────────────────────────────────
test "integration: L2 dst MAC = aa:bb:cc:dd:ee:ff", ->
  assert e.dst == "\xaa\xbb\xcc\xdd\xee\xff", "dst MAC mismatch"

test "integration: L2 src MAC = 11:22:33:44:55:66", ->
  assert e.src == "\x11\x22\x33\x44\x55\x66", "src MAC mismatch"

test "integration: L2 EtherType = 0x0800 (IPv4)", ->
  assert e.protocol == 0x0800, "expected 0x0800, got #{string.format('0x%04x', e.protocol)}"

-- ── Layer 3 ──────────────────────────────────────────────────────────────────
test "integration: L3 IPv4 version = 4", ->
  assert ip.version == 4, "expected 4, got #{ip.version}"

test "integration: L3 IPv4 protocol = 17 (UDP)", ->
  assert ip.protocol == 17, "expected 17, got #{ip.protocol}"

test "integration: L3 IPv4 src = 192.168.1.1", ->
  assert ip_mod.ip42s(ip.src) == "192.168.1.1", "src IP mismatch"

test "integration: L3 IPv4 dst = 1.1.1.1", ->
  assert ip_mod.ip42s(ip.dst) == "1.1.1.1", "dst IP mismatch"

-- ── Layer 4 ──────────────────────────────────────────────────────────────────
test "integration: L4 UDP src port = 1234", ->
  assert u.spt == 1234, "expected spt=1234, got #{u.spt}"

test "integration: L4 UDP dst port = 443", ->
  assert u.dpt == 443, "expected dpt=443, got #{u.dpt}"

-- ── Layer 7 QUIC header ───────────────────────────────────────────────────────
test "integration: L7 QUIC long header flag set", ->
  assert q.long_header, "expected long_header=true"

test "integration: L7 QUIC version = 1", ->
  assert q.version == 1, "expected version=1, got #{q.version}"

test "integration: L7 QUIC DCID = 8394c8f03e515708", ->
  assert bin2hex(q.dst_connection_id) == "8394c8f03e515708",
    "DCID mismatch: #{bin2hex q.dst_connection_id}"

test "integration: L7 QUIC pkt_type = 0x00 (Initial)", ->
  assert q.pkt_type == 0x00, "expected pkt_type=0x00, got #{string.format('0x%02x', q.pkt_type)}"

test "integration: L7 QUIC pkt_length = 1182", ->
  -- 1182 = 4 (PN) + 1162 (frames) + 16 (AEAD tag)
  assert q.pkt_length == 1182, "expected 1182, got #{q.pkt_length}"

test "integration: L7 QUIC protected PN = 7b9aec34", ->
  pn_abs = q.pn_off  -- absolute in frame
  got = bin2hex frame\sub pn_abs, pn_abs + 3
  assert got == "7b9aec34", "protected PN mismatch: #{got}"

-- ── Crypto-dependent tests ────────────────────────────────────────────────────
ok_backend, backend = pcall require, "ipparse.lib.crypto.backend.ffi_openssl"

if ok_backend
  keys = require "ipparse.l4.quic.v1.keys"
  prot = require "ipparse.l4.quic.v1.protection"

  -- Derive initial secrets from DCID
  dcid = q.dst_connection_id
  client_secret = keys.derive_initial_secrets dcid
  key, iv, hp_key = keys.derive_keys client_secret

  -- Remove header protection from the QUIC-only bytes
  hdr_bytes, pn, pn_len = prot.remove_header_protection quic, pn_off_quic, hp_key, true, 0, backend

  -- Build AAD: unprotected header bytes up to and including PN field
  aad = string.char unpack hdr_bytes, 1, pn_off_quic + pn_len - 1

  -- Decrypt payload
  payload_off = pn_off_quic + pn_len
  plaintext, decrypt_err = prot.decrypt_payload quic, payload_off, key, iv, pn, aad, backend

  test "integration: QUIC HP removed - first byte = 0xc3", ->
    assert hdr_bytes[1] == 0xc3,
      "expected 0xc3, got #{string.format('0x%02x', hdr_bytes[1])}"

  test "integration: QUIC HP removed - packet number = 2", ->
    assert pn == 2, "expected pn=2, got #{pn}"

  test "integration: QUIC HP removed - AAD matches RFC 9001 §A.2 unprotected header", ->
    expected = "c300000001088394c8f03e5157080000449e00000002"
    assert bin2hex(aad) == expected,
      "AAD mismatch:\ngot:      #{bin2hex aad}\nexpected: #{expected}"

  test "integration: QUIC payload decrypted successfully (1162 bytes)", ->
    assert plaintext ~= nil, "decrypt failed: #{decrypt_err}"
    assert #plaintext == 1162, "expected 1162 bytes, got #{#plaintext}"

  test "integration: QUIC plaintext starts with CRYPTO frame (0x06)", ->
    assert plaintext ~= nil, "no plaintext"
    assert string.byte(plaintext, 1) == 0x06,
      "expected CRYPTO frame type 0x06, got #{string.format('0x%02x', string.byte(plaintext, 1))}"

  test "integration: SNI 'example.com' found in decrypted ClientHello", ->
    assert plaintext ~= nil, "no plaintext"
    pos = plaintext\find "example.com", 1, true
    assert pos ~= nil, "SNI 'example.com' not found in decrypted payload"

else
  test "integration: crypto tests skipped (libcrypto not available)", ->
    true

util.summary "integration"
