--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Generic TCP stream defragmenter.
-- Accumulates TCP payloads by session key; clears on FIN/RST; purges by age.
-- @module l4.tcp_stream

{:band} = require "ipparse.lib.bit_compat"

--- Creates a new TCP stream defragmenter.
-- @tparam[opt] function check_complete  Predicate (buf) -> bool. Default: always
--   true (each segment with payload is immediately complete). When provided,
--   feed returns nil until the predicate passes, then auto-clears the session.
-- @treturn table State with :feed, :clear and :purge methods.
new = (check_complete=(-> true)) ->
  sessions = {}

  {
    --- Feed a TCP segment into the stream.
    -- @tparam string key      Session key (e.g. "src|sport|dst|dport").
    -- @tparam string payload  TCP payload bytes (may be "").
    -- @tparam number flags    Raw TCP flags byte.
    -- @tparam number init_seq Sequence number of this segment.
    -- @treturn string|nil  Complete buffer (nil on FIN/RST, empty payload, or incomplete).
    -- @treturn number|nil  init_seq of the first segment in this session.
    -- @treturn boolean|nil true if this was the first segment for this session.
    feed: (key, payload, flags, init_seq) ->
      if band(flags, 0x05) != 0   -- FIN or RST
        sessions[key] = nil
        return nil
      return nil if payload == ""
      first_seg = sessions[key] == nil
      if first_seg
        sessions[key] = { buf: payload, :init_seq, timestamp: os.time! }
      else
        sessions[key].buf ..= payload
      entry = sessions[key]
      if check_complete entry.buf
        stored_seq = entry.init_seq
        buf = entry.buf
        sessions[key] = nil
        return buf, stored_seq, first_seg
      nil

    --- Clear a session explicitly.
    -- @tparam string key
    clear: (key) -> sessions[key] = nil

    --- Drop every tracked session (vidage en place, références préservées).
    reset: -> sessions[k] = nil for k in pairs sessions

    --- Purge sessions older than max_age seconds.
    -- @tparam[opt=300] number max_age
    purge: (max_age=300) ->
      now = os.time!
      for key, entry in pairs sessions
        if now - entry.timestamp > max_age
          sessions[key] = nil
  }

{ :new }
