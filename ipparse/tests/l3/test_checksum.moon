--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
pack: sp = require "ipparse.lib.pack_compat"
{:checksum, :checksum6} = require"ipparse.l3.lib"
ip4 = require"ipparse.l3.ip4"

test "checksum of 0xffff is 0", ->
  result = checksum "\255\255"
  assert result == 0, "checksum(0xffff) should be 0, got #{result}"

test "checksum of 0x0000 is 0xffff", ->
  result = checksum "\000\000"
  assert result == 0xffff, "checksum(0x0000) should be 0xffff, got #{result}"

test "checksum of packed header is 0", ->
  -- Build a valid IPv4 header using new+pack, then verify its checksum
  hdr = ip4.new {
    src: ip4.s2ip4 "192.168.1.1"
    dst: ip4.s2ip4 "192.168.1.2"
    protocol: 6
    options: ""
  }
  raw = tostring hdr
  -- The header is 20 bytes; checksum of those 20 bytes should be 0
  header_bytes = raw\sub 1, 20
  result = checksum header_bytes
  assert result == 0, "checksum of valid IP header should be 0, got #{result}"

test "checksum odd-length pads with zero", ->
  -- Odd-length input should be padded; "\255" = "\255\000" padded → checksum = 0xff00 → bnot = 0x00ff
  result = checksum "\255"
  assert result == 0x00ff, "checksum(\\255) should be 0x00ff, got #{result}"

test "checksum6 matches IPv6 pseudo-header formula", ->
  src = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  dst = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  payload = "abcdef"
  got = checksum6 src, dst, 17, payload
  expected = checksum sp(">c16c16 I4 xxx B c#{#payload}", src, dst, #payload, 17, payload)
  assert got == expected, "checksum6 mismatch: got #{got}, expected #{expected}"
test "checksum6 stable across payload lengths (frozen values)", ->
  src = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  dst = string.char 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  assert checksum6(src, dst, 17, "abcdef") == 31302, "checksum6 (6 bytes) changed"
  assert checksum6(src, dst, 17, "hello world!!") == 61820, "checksum6 (13 bytes) changed"
  assert checksum6(src, dst, 17, "xyz") == 45564, "checksum6 (3 bytes, odd) changed"

-- Référence indépendante : la formule RFC 1071 écrite à la main (somme des
-- mots 16 bits en arithmétique pure, retenue pliée, complément à un).
-- Sert de témoin d'équivalence à toute réécriture de `checksum`.
ref_checksum = (s) ->
  s = s .. "\0" if #s % 2 == 1
  cksm = 0
  for i = 1, #s, 2
    a, b = string.byte s, i, i + 1
    cksm += a * 256 + b
  -- Fold carry into the low 16 bits using integer arithmetic only: no
  -- math.floor, no floating-point division, no bitwise operators, so that
  -- this reference stays independent of the implementation (which uses rshift)
  -- and runs on LuaJIT 5.1 as well as on Lunatik's integer-only kernel Lua.
  while true
    low = cksm % 0x10000
    -- carry = floor(cksm / 0x10000), computed by repeated subtraction.
    carry = 0
    tmp = cksm - low
    while tmp >= 0x10000
      tmp -= 0x10000
      carry += 1
    break if carry == 0
    cksm = low + carry
  0xFFFF - (cksm % 0x10000)

-- Séquence d'octets déterministe couvrant les 256 valeurs (aucune arithmétique
-- dépendante de la précision des flottants).
_pattern_parts = {}
for i = 0, 255
  _pattern_parts[#_pattern_parts + 1] = string.char i
PATTERN = table.concat _pattern_parts

test "checksum matches the RFC 1071 reference on rotated buffers", ->
  for len = 1, 67
    rot = (len * 7) % 256 + 1
    buf = (PATTERN .. PATTERN)\sub rot, rot + len - 1
    got, want = checksum(buf), ref_checksum(buf)
    assert got == want,
      "checksum len=#{len}: got #{got}, reference #{want}"
  -- Longueur paire de taille respectable (couvre la boucle de pli de retenue).
  big = (string.rep PATTERN, 16)\sub 1, 4000
  assert checksum(big) == ref_checksum(big), "checksum on 4000-byte buffer changed"

test "checksum of a DNS-over-UDP payload is stable (frozen value)", ->
  -- Octets réels d'une réponse DNS courte : garde-fou contre une réécriture
  -- qui changerait la gestion de la longueur impaire ou le pli de retenue.
  payload = string.char 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
  assert checksum(payload) == ref_checksum(payload), "DNS payload checksum changed"
  assert checksum(payload) == 0x9ddc, "DNS payload checksum frozen value changed"

util.summary "l3/checksum"
