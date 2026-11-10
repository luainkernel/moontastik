--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Tests for the TLS handshake extension modules (extension, server_name,
-- supported_versions), including malformed/truncated inputs.

util = require"ipparse.lib.util"
{:test} = util
ext = require"ipparse.l7.tls.handshake.extension"
sn = require"ipparse.l7.tls.handshake.extension.server_name"
sv = require"ipparse.l7.tls.handshake.extension.supported_versions"
hs = require"ipparse.l7.tls.handshake"
sp = require("ipparse.lib.pack_compat").pack

-- extension: type 0x0000 (server_name), data "abc"
test "extension: parse round-trips pack", ->
  raw = sp ">H s2", 0x0000, "abc"
  e, off = ext.parse raw, 1
  assert e and e.type == 0 and e.data == "abc", "extension parse failed"
  assert off == #raw + 1, "offset should be past the extension"
  assert tostring(e) == raw, "pack should round-trip"

test "extension: truncated header returns nil", ->
  e, off = ext.parse "\000", 1
  assert e == nil and off == 1, "should return nil, input offset"

test "extension: truncated data returns nil", ->
  raw = sp ">HH", 0x0000, 10  -- announces 10 bytes, provides none
  e, off = ext.parse raw, 1
  assert e == nil and off == 1, "should return nil on short data"

-- server_name: list with one host_name entry
sn_entry = sp ">B s2", 0, "example.com"
sn_raw = sp(">H", #sn_entry) .. sn_entry

test "server_name: parses single host_name", ->
  s = sn.parse sn_raw, 1
  assert s and s.name == "example.com", "expected example.com, got #{s and s.name}"
  assert not s.incomplete, "should be complete"

test "server_name: truncated list returns nil with error", ->
  s, off, err = sn.parse "\000", 1
  assert s == nil and err, "should return nil, off, err"

test "server_name: truncated entry flagged incomplete", ->
  bad = sp(">H", 20) .. "\000\000\016ab"  -- announces 16-byte name, has 2
  s = sn.parse bad, 1
  assert s and s.incomplete, "should be flagged incomplete"

-- supported_versions
test "supported_versions: ServerHello selected version", ->
  v = sv.parse sp(">H", 0x0304), 1
  assert v and v.selected == 0x0304, "expected selected TLS 1.3"

test "supported_versions: ClientHello list", ->
  raw = sp ">B HH", 4, 0x0304, 0x0303
  v, off = sv.parse raw, 1
  assert v and v.versions and #v.versions == 2, "expected 2 versions"
  assert v.versions[1] == 0x0304 and v.versions[2] == 0x0303, "version values mismatch"
  assert off == #raw + 1, "offset should be past the list"

test "supported_versions: truncated list returns nil", ->
  v, off = sv.parse sp(">B H", 8, 0x0304), 1  -- announces 8 bytes, has 2
  assert v == nil and off == 1, "should return nil on truncated list"

test "supported_versions: empty data returns nil", ->
  v = sv.parse "", 1
  assert v == nil, "should return nil on empty data"

test "handshake: message_types matches the IANA registry", ->
  assert hs.message_types.finished == 20, "finished should be 20"
  assert hs.message_types[24] == "key_update", "[24] should be key_update"
  assert hs.message_types.encrypted_extensions == 8, "encrypted_extensions should be 8"
  assert hs.message_types[1] == "client_hello", "[1] should be client_hello"

tls = require "ipparse.l7.tls"

test "handshake: pack round-trips a 3-byte length", ->
  raw = hs.pack { type: 1, len: 0x12345 }
  assert #raw == 4, "expected 4-byte header, got #{#raw}"
  h, off = hs.parse raw, 1
  assert h and h.type == 1, "type mismatch"
  assert h.len == 0x12345, "expected len 0x12345, got #{h.len}"
  assert off == 5, "offset should be past the header"
  assert tostring(h) == raw, "tostring should repack identically"

test "handshake: parse_ciphers returns every 16-bit value", ->
  raw = sp ">HHH", 0x1301, 0x1302, 0xc02f
  c = hs.parse_ciphers raw
  assert #c == 3, "expected 3 ciphers, got #{#c}"
  assert c[1] == 0x1301 and c[3] == 0xc02f, "cipher values mismatch"

test "handshake: parse_compressions returns every byte", ->
  c = hs.parse_compressions "\000\001\002"
  assert #c == 3, "expected 3 compressions, got #{#c}"
  assert c[1] == 0 and c[3] == 2, "compression values mismatch"

test "handshake: iter_extensions walks every extension", ->
  raw = sp(">H s2", 0x0000, "abc") .. sp(">H s2", 0x002b, "de")
  types = { }
  for e in hs.iter_extensions raw
    types[#types + 1] = e.type
  assert #types == 2, "expected 2 extensions, got #{#types}"
  assert types[1] == 0 and types[2] == 0x002b, "extension types mismatch"

test "handshake: iter_extensions honours an explicit offset and length", ->
  raw = sp(">H s2", 0x0000, "abc") .. sp(">H s2", 0x002b, "de")
  second = sp ">H s2", 0x002b, "de"
  types = { }
  for e in hs.iter_extensions raw, #raw - #second + 1, #second
    types[#types + 1] = e.type
  assert #types == 1 and types[1] == 0x002b, "expected only the second extension"

test "tls: record header pack round-trips", ->
  raw = tls.pack { type: 0x16, ver: 3, subver: 3, len: 4 }
  assert #raw == 5, "expected 5-byte header, got #{#raw}"
  r, off = tls.parse raw, 1
  assert r and r.type == 0x16, "type mismatch"
  assert r.ver == 3 and r.subver == 3, "version mismatch"
  assert r.len == 4, "expected len 4"
  assert r.data_off == 6, "data offset should be past the header"
  assert tostring(r) == raw, "tostring should repack identically"

test "server_name: parse_entry honours the default offset", ->
  raw = sp ">B s2", 0, "example.org"
  e, off = sn.parse_entry raw
  assert e and e.type == 0 and e.name == "example.org", "entry mismatch"
  assert off == #raw + 1, "offset should be past the entry"
  assert sn.pack_entry(e) == raw, "pack_entry should round-trip"

test "server_name: pack round-trips a parsed list", ->
  s = sn.parse sn_raw, 1
  assert sn.pack(s) == sn_raw, "pack should reproduce the list bytes"

test "server_name: empty name list packs to a zero length", ->
  assert sn.pack({}) == "\000\000", "empty list should pack as 0x0000"

test "supported_versions: list of three versions round-trips", ->
  raw = sp ">B HHH", 6, 0x0304, 0x0303, 0x0301
  v, off = sv.parse raw, 1
  assert v and #v.versions == 3, "expected 3 versions"
  assert v.versions[1] == 0x0304 and v.versions[3] == 0x0301, "version values mismatch"
  assert off == #raw + 1, "offset should be past the list"
  assert tostring(v) == raw, "tostring should repack the list identically"

test "supported_versions: selected version round-trips", ->
  raw = sp ">H", 0x0304
  v = sv.parse raw, 1
  assert tostring(v) == raw, "tostring should repack the selected version"

util.summary "l7/tls/handshake"
