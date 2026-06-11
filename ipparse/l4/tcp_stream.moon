--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Generic TCP stream defragmenter.
-- Accumulates TCP payloads by session key; clears on FIN/RST; purges by age.
-- Memory is bounded: per-session buffers are capped (`max_buf`) and so is the
-- number of tracked sessions (`max_sessions`, oldest dropped first), so a
-- flood of never-completing streams cannot grow state without limit.
-- @module l4.tcp_stream

{:band} = require "ipparse.lib.bit_compat"
:concat = table

--- Creates a new TCP stream defragmenter.
-- @tparam[opt] function check_complete  Predicate (buf) -> bool. Default: always
--   true (each segment with payload is immediately complete). When provided,
--   feed returns nil until the predicate passes, then auto-clears the session.
-- @tparam[opt] table opts Options: `max_buf` (bytes per session, default 1 MiB),
--   `max_sessions` (default 1024).
-- @treturn table State with :feed, :clear, :reset and :purge methods.
new = (check_complete=(-> true), opts={}) ->
  max_buf = opts.max_buf or 0x100000
  max_sessions = opts.max_sessions or 1024
  sessions = {}
  count = 0

  drop = (key) ->
    if sessions[key] != nil
      sessions[key] = nil
      count -= 1

  drop_oldest = ->
    oldest_key, oldest_ts = nil, nil
    for key, entry in pairs sessions
      if not oldest_ts or entry.timestamp < oldest_ts
        oldest_key, oldest_ts = key, entry.timestamp
    drop oldest_key if oldest_key

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
        drop key
        return nil
      return nil if payload == ""
      entry = sessions[key]
      first_seg = entry == nil
      if first_seg
        drop_oldest! if count >= max_sessions
        entry = { segments: {payload}, total: #payload, :init_seq, timestamp: os.time! }
        sessions[key] = entry
        count += 1
      else
        entry.segments[#entry.segments + 1] = payload
        entry.total += #payload
      if entry.total > max_buf
        drop key
        return nil
      buf = concat entry.segments
      if check_complete buf
        stored_seq = entry.init_seq
        drop key
        return buf, stored_seq, first_seg
      -- Collapse the segments we just concatenated so the next feed does not
      -- redo the whole join.
      entry.segments = {buf}
      nil

    --- Clear a session explicitly.
    -- @tparam string key
    clear: (key) -> drop key

    --- Drop every tracked session (vidage en place, références préservées).
    reset: ->
      sessions[k] = nil for k in pairs sessions
      count = 0

    --- Purge sessions older than max_age seconds.
    -- @tparam[opt=300] number max_age
    purge: (max_age=300) ->
      now = os.time!
      for key, entry in pairs sessions
        if now - entry.timestamp > max_age
          drop key
  }

{ :new }
