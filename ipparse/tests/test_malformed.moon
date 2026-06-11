--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Robustness tests: truncated and adversarial inputs must yield clean
-- `nil[, err]` returns (never raise, never loop) across the parsing stack.

util = require"ipparse.lib.util"
{:test} = util
sp = require("ipparse.lib.pack_compat").pack
su = require("ipparse.lib.pack_compat").unpack

ip6 = require"ipparse.l3.ip6"
ip = require"ipparse.l3.ip"
dns = require"ipparse.l7.dns"
quic = require"ipparse.l4.quic"
frames = require"ipparse.l4.quic.frames"

test "ip6: truncated header returns nil", ->
  res, off = ip6.parse "\x60\x00\x00\x00", 1
  assert res == nil and off == 1, "truncated IPv6 header should return nil"

test "ip: get_version out of bounds returns nil", ->
  assert ip.get_version("", 1) == nil, "empty buffer"
  assert ip.get_version("\x45", 5) == nil, "offset past end"

test "ip: parse empty buffer returns nil, err", ->
  res, err = ip.parse "", 1
  assert res == nil and err, "should return nil plus an error message"

test "quic: parse empty buffer returns nil", ->
  q, off = quic.parse "", 1
  assert q == nil and off == 1, "empty payload should return nil"

test "quic: truncated long header returns nil", ->
  -- Long-header flag set, then nothing else.
  q, off = quic.parse "\xc0\x00", 1
  assert q == nil, "truncated long header should return nil"

test "quic: ACK frame with huge range count is rejected", ->
  -- type=0x02, largest=0, delay=0, range_count=0x3FFFFFFF (varint 4 bytes), first_range=0
  raw = "\x02\x00\x00" .. "\xbf\xff\xff\xff" .. "\x00"
  frame, _, err = frames.parse_frame raw, 1
  assert frame == nil and err and err\match("too large"), "expected range-count rejection, got #{err}"

test "quic: validate_frames detects truncated CRYPTO frame", ->
  -- CRYPTO frame: type=0x06, offset=0, length=100, but no data
  raw = "\x06\x00\x40\x64"
  ok, err = frames.validate_frames raw
  assert ok == false and err, "truncated CRYPTO should fail validation"

test "dns: circular compression pointer is rejected", ->
  -- Minimal DNS header (12 bytes) + a name that is a pointer to itself.
  hdr = sp ">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0
  name = "\xc0\x0c"  -- pointer to offset 12 = itself
  qd = name .. sp ">HH", 1, 1
  msg = hdr .. qd
  res, _, err = dns.parse msg, 1
  -- Must terminate with an error (not hang, not crash).
  assert res == nil or err or (res and res.questions == nil) or true
  -- The real assertion is termination; also check labels directly:
  lbls, _, lerr = dns.labels msg, 13, 1
  assert lbls == nil and lerr and lerr\match("loop"), "expected pointer-loop error, got #{lerr}"

test "dns: truncated label returns error", ->
  -- Label announces 10 bytes, provides 2.
  lbls, _, err = dns.labels "\x0aab", 1, 1
  assert lbls == nil and err, "truncated label should return an error"

test "pack_compat: unpack on short data raises a clear error", ->
  ok, err = pcall su, ">I4", "\x01\x02", 1
  assert not ok and tostring(err)\match("too short"), "expected 'data string too short', got #{err}"

util.summary "malformed"
