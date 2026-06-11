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

util.summary "l4/tcp_stream"
