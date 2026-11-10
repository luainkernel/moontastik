--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
ip4 = require"ipparse.l3.ip4"
frag = require"ipparse.l3.fragmented_ip4"

src = ip4.s2ip4 "1.2.3.4"
dst = ip4.s2ip4 "5.6.7.8"

build = (id, ff, data) ->
  raw = ip4.pack ip4.new {
    :src
    :dst
    protocol: 17
    :id
    :ff
    :data
  }
  ip = ip4.parse raw, 1
  raw, ip

test "non-fragmented packet is returned immediately", ->
  frag.reset!
  raw, ip = build 1, 0, "hello"
  payload, header = frag.collect ip, raw
  assert payload == "hello", "expected 'hello', got '#{payload}'"
  assert header == ip, "expected the original header"

test "two fragments in order are reassembled", ->
  frag.reset!
  raw1, ip1 = build 2, 0x2000, "ABCDEFGH"
  raw2, ip2 = build 2, 1, "IJKL"
  pending = frag.collect ip1, raw1
  assert pending == nil, "first fragment should be pending"
  payload, header = frag.collect ip2, raw2
  assert payload == "ABCDEFGHIJKL", "expected 'ABCDEFGHIJKL', got '#{payload}'"
  assert header == ip1, "header should be the first fragment's header"

test "three fragments out of order (last first)", ->
  frag.reset!
  raw1, ip1 = build 3, 0x2000, "01234567"
  raw2, ip2 = build 3, 0x2001, "89abcdef"
  raw3, ip3 = build 3, 2, "ghij"
  assert frag.collect(ip3, raw3) == nil, "last fragment alone should be pending"
  assert frag.collect(ip2, raw2) == nil, "middle fragment alone should be pending"
  payload, header = frag.collect ip1, raw1
  assert payload == "0123456789abcdefghij", "got '#{payload}'"
  assert header == ip1, "header should be the first fragment's header"

test "hole in the middle keeps the flow pending", ->
  frag.reset!
  raw1, ip1 = build 4, 0x2000, "ABCDEFGH"
  raw3, ip3 = build 4, 2, "WXYZ"
  assert frag.collect(ip1, raw1) == nil, "first fragment should be pending"
  assert frag.collect(ip3, raw3) == nil, "a hole must not complete the flow"

test "duplicate fragment is tolerated", ->
  frag.reset!
  raw1, ip1 = build 5, 0x2000, "ABCDEFGH"
  raw2, ip2 = build 5, 1, "IJKL"
  assert frag.collect(ip1, raw1) == nil, "first fragment should be pending"
  assert frag.collect(ip1, raw1) == nil, "duplicate first fragment should stay pending"
  payload, header = frag.collect ip2, raw2
  assert payload == "ABCDEFGHIJKL", "got '#{payload}'"
  assert header == ip1, "header should be the first fragment's header"

test "two interleaved flows are kept separate", ->
  frag.reset!
  a1raw, a1 = build 10, 0x2000, "AAAAAAAA"
  a2raw, a2 = build 10, 1, "aaaa"
  b1raw, b1 = build 11, 0x2000, "BBBBBBBB"
  b2raw, b2 = build 11, 1, "bbbb"
  assert frag.collect(a1, a1raw) == nil, "A first should be pending"
  assert frag.collect(b1, b1raw) == nil, "B first should be pending"
  payload_a, header_a = frag.collect a2, a2raw
  assert payload_a == "AAAAAAAAaaaa", "got '#{payload_a}'"
  assert header_a == a1, "A header should be the first fragment's header"
  payload_b, header_b = frag.collect b2, b2raw
  assert payload_b == "BBBBBBBBbbbb", "got '#{payload_b}'"
  assert header_b == b1, "B header should be the first fragment's header"

test "MF fragment length not a multiple of 8 is rejected", ->
  frag.reset!
  raw, ip = build 20, 0x2000, "ABCDE"
  res, err = frag.collect ip, raw
  assert res == nil, "expected nil result"
  assert err == "invalid fragment length", "got '#{err}'"

test "fragment exceeding 65535 bytes is rejected", ->
  frag.reset!
  raw, ip = build 30, 0x2000 + 8191, "ABCDEFGH"
  res, err = frag.collect ip, raw
  assert res == nil, "expected nil result"
  assert err == "fragment exceeds 65535 bytes", "got '#{err}'"

test "oldest pending flow is evicted beyond MAX_PENDING", ->
  frag.reset!
  first_raw, first_ip = nil, nil
  last_raw, last_ip = nil, nil
  for i = 1, 65
    raw, ip = build i, 0x2000, "ABCDEFGH"
    frag.collect ip, raw
    if i == 1
      first_raw, first_ip = raw, ip
    if i == 65
      last_raw, last_ip = raw, ip
  raw2, ip2 = build 1, 1, "WXYZ"
  evicted = frag.collect ip2, raw2
  assert evicted == nil, "evicted flow must not complete"
  raw3, ip3 = build 65, 1, "WXYZ"
  payload, header = frag.collect ip3, raw3
  assert payload == "ABCDEFGHWXYZ", "got '#{payload}'"
  assert header == last_ip, "header should be the last flow's first fragment"

test "truncated packet is rejected", ->
  frag.reset!
  raw, ip = build 40, 0, "hello"
  short = raw\sub 1, #raw - 1
  res, err = frag.collect ip, short
  assert res == nil, "expected nil result"
  assert err == "truncated packet", "got '#{err}'"

test "completed flows do not grow the eviction queue", ->
  frag.reset!
  for i = 1, 1000
    raw1, ip1 = build i, 0x2000, "ABCDEFGH"
    raw2, ip2 = build i, 1, "IJKL"
    assert frag.collect(ip1, raw1) == nil, "flow #{i} first fragment should be pending"
    payload = frag.collect ip2, raw2
    assert payload == "ABCDEFGHIJKL", "flow #{i} should complete, got '#{payload}'"
  pending, queued = frag.stats!
  assert pending == 0, "pending should be 0, got #{pending}"
  assert queued == 0, "eviction queue should be empty, got #{queued}"

test "eviction queue holds one entry per incomplete flow", ->
  frag.reset!
  for i = 1, 10
    raw, ip = build i, 0x2000, "ABCDEFGH"
    assert frag.collect(ip, raw) == nil, "flow #{i} should be pending"
  pending, queued = frag.stats!
  assert pending == 10, "pending should be 10, got #{pending}"
  assert queued == 10, "eviction queue should hold 10 entries, got #{queued}"

test "reused key evicts the oldest living flow, not a newer one", ->
  frag.reset!
  a1raw, a1 = build 7, 0x2000, "AAAAAAAA"
  assert frag.collect(a1, a1raw) == nil, "A first should be pending"
  a2raw, a2 = build 7, 1, "aaaa"
  payload = frag.collect a2, a2raw
  assert payload == "AAAAAAAAaaaa", "A should complete, got '#{payload}'"
  n1raw, n1 = build 7, 0x2000, "BBBBBBBB"
  assert frag.collect(n1, n1raw) == nil, "new id 7 flow should be pending"
  for i = 100, 162
    raw, ip = build i, 0x2000, "CCCCCCCC"
    assert frag.collect(ip, raw) == nil, "flow #{i} should be pending"
  pending, queued = frag.stats!
  assert pending == 64, "pending should be 64, got #{pending}"
  assert queued == 64, "eviction queue should hold 64 entries, got #{queued}"
  raw, ip = build 200, 0x2000, "DDDDDDDD"
  assert frag.collect(ip, raw) == nil, "65th flow should be pending"
  pending, queued = frag.stats!
  assert pending == 64, "pending should stay at 64, got #{pending}"
  assert queued == 64, "eviction queue should hold 64 entries, got #{queued}"
  r200raw, r200 = build 200, 1, "dddd"
  payload = frag.collect r200, r200raw
  assert payload == "DDDDDDDDdddd", "newest flow should survive, got '#{payload}'"
  n2raw, n2 = build 7, 1, "bbbb"
  assert frag.collect(n2, n2raw) == nil, "oldest living flow (id 7) must have been evicted"
  r100raw, r100 = build 100, 1, "cccc"
  payload = frag.collect r100, r100raw
  assert payload == "CCCCCCCCcccc", "a recent flow should survive, got '#{payload}'"
  r150raw, r150 = build 150, 1, "eeee"
  payload = frag.collect r150, r150raw
  assert payload == "CCCCCCCCeeee", "another recent flow should survive, got '#{payload}'"

util.summary "l3/fragmented_ip4"
