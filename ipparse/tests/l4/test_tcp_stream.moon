--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
tcp_stream = require"ipparse.l4.tcp_stream"

test "tcp_stream: default predicate returns each payload immediately", ->
  s = tcp_stream.new!
  buf, seq, first = s.feed "k", "hello", 0x10, 42
  assert buf == "hello" and seq == 42 and first == true, "immediate completion failed"

test "tcp_stream: accumulates until predicate passes", ->
  s = tcp_stream.new (buf) -> #buf >= 6
  assert s.feed("k", "abc", 0x10, 1) == nil, "should be incomplete"
  buf = s.feed "k", "defg", 0x10, 2
  assert buf == "abcdefg", "expected reassembled buffer, got #{buf}"

test "tcp_stream: FIN clears the session", ->
  s = tcp_stream.new (buf) -> #buf >= 6
  s.feed "k", "abc", 0x10, 1
  s.feed "k", "", 0x01, 2          -- FIN
  buf = s.feed "k", "123456", 0x10, 3
  assert buf == "123456", "buffer should only contain post-FIN data, got #{buf}"

test "tcp_stream: per-session buffer is capped", ->
  s = tcp_stream.new ((buf) -> #buf >= 6), max_buf: 8
  assert s.feed("k", "12345", 0x10, 1) == nil, "incomplete"
  -- This append exceeds max_buf: the session is dropped, nothing returned.
  assert s.feed("k", "abcdefgh", 0x10, 2) == nil, "overflow should drop session"
  -- A fresh segment completes on its own: prior state really was dropped.
  buf = s.feed "k", "123456", 0x10, 3
  assert buf == "123456", "expected fresh buffer after overflow, got #{buf}"

test "tcp_stream: session count is capped (oldest dropped)", ->
  s = tcp_stream.new ((buf) -> #buf >= 6), max_sessions: 2
  s.feed "a", "abc", 0x10, 1
  s.feed "b", "abc", 0x10, 1
  s.feed "c", "abc", 0x10, 1  -- evicts the oldest session
  buf = s.feed "c", "def", 0x10, 2
  assert buf == "abcdef", "session c should have survived eviction, got #{buf}"

test "tcp_stream: reset drops everything", ->
  s = tcp_stream.new (buf) -> #buf >= 6
  s.feed "k", "abc", 0x10, 1
  s.reset!
  buf = s.feed "k", "123456", 0x10, 2
  assert buf == "123456", "buffer should only contain post-reset data, got #{buf}"

test "tcp_stream: purge drops sessions older than max_age", ->
  now = 0
  s = tcp_stream.new ((buf) -> #buf >= 6), clock: -> now, clock_hz: 1000
  s.feed "old", "abc", 0x10, 1
  now = 5000  -- 5 s later
  s.feed "new", "abc", 0x10, 1
  s.purge 3   -- max_age = 3 s => 3000 ticks
  -- The recent session survived: appending completes its buffer.
  buf = s.feed "new", "def", 0x10, 2
  assert buf == "abcdef", "recent session should survive purge, got #{buf}"
  -- The old session was dropped: a new segment starts from scratch.
  buf = s.feed "old", "def", 0x10, 2
  assert buf == nil, "old session should have been purged, got #{buf}"

test "tcp_stream: clock_hz without clock raises", ->
  ok, err = pcall tcp_stream.new, nil, clock_hz: 1000
  assert not ok, "expected an error when clock_hz is given without clock"
  assert tostring(err)\find("clock_hz"), "error should mention clock_hz, got #{err}"

test "tcp_stream: empty payload is ignored", ->
  s = tcp_stream.new!
  assert s.feed("k", "", 0x10, 1) == nil, "empty payload should return nil"
  buf, seq, first = s.feed "k", "hello", 0x10, 1
  assert buf == "hello" and seq == 1 and first == true, "no session should have been created"

test "tcp_stream: clear drops a single session", ->
  s = tcp_stream.new (buf) -> #buf >= 6
  s.feed "k", "abc", 0x10, 1
  s.clear "k"
  buf, seq, first = s.feed "k", "123456", 0x10, 2
  assert buf == "123456", "expected fresh buffer after clear, got #{buf}"
  assert seq == 2 and first == true, "clear should reset sequence state"

test "tcp_stream: purge uses the default max_age", ->
  now = 0
  s = tcp_stream.new ((buf) -> #buf >= 6), clock: -> now, clock_hz: 1000
  s.feed "old", "abc", 0x10, 1
  now = 301000  -- 301 s later, past the default 300 s
  s.purge!
  buf = s.feed "old", "def", 0x10, 2
  assert buf == nil, "default purge should have dropped the old session"

util.summary "l4/tcp_stream"
