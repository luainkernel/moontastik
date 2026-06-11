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
sp = require("ipparse.lib.pack_compat").pack

-- extension: type 0x0000 (server_name), data "abc"
test "extension: parse round-trips pack", ->
  raw = sp ">H s2", 0x0000, "abc"
  e, off = ext.parse raw, 1
  assert e and e.type == 0 and e.data == "abc", "extension parse failed"
  assert off == #raw + 1, "offset should be past the extension"
  assert tostring(e) == raw, "pack should round-trip"

test "extension: truncated header returns nil", ->
  e, off = ext.parse "\x00", 1
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
  s, off, err = sn.parse "\x00", 1
  assert s == nil and err, "should return nil, off, err"

test "server_name: truncated entry flagged incomplete", ->
  bad = sp(">H", 20) .. "\x00\x00\x10ab"  -- announces 16-byte name, has 2
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

util.summary "l7/tls/handshake"
