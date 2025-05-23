--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

IP4 = require"ipparse.l3.ip4"
new: data_new = require"data"
:sort = table

fragmented = {}

collect: =>
  id = @id
  fragments = fragmented[id] or {}
  fragmented[id] = fragments
  _skb, off, data_off, data_len, mf = @skb, @off, @data_off, @data_len, @mf
  frag_off = @fragmentation_off << 3
  total_len = off + frag_off + data_off + data_len
  -- 64KB is the theoretical maximum, 10KB a reasonable max len default
  max_len = total_len > 10240 and 65535 or 10240
  return false, "Invalid size" if max_len > 65535
  skb = fragments.skb
  if skb
    if #skb < max_len  -- Handle the case of a very big jumbo frame
      tmp = data_new max_len
      tmp\setstring 0, skb\getstring 0
      skb = tmp
  else
    skb = data_new max_len
  fragments.skb = skb
  if frag_off == 0
    skb\setstring 0, _skb\getstring 0, (off + data_off + data_len - 1)
  else
    offset = off + data_off
    max_offset = offset + data_len - 1
    return false, "Invalid data offset" if max_offset > #_skb
    skb\setstring (frag_off + offset), _skb\getstring offset, max_offset
  fragments[#fragments+1] = {:frag_off, :off, :data_off, :data_len, :mf}
  sort fragments, (a, b) -> a.frag_off < b.frag_off
  lastfrag = fragments[#fragments]
  return if lastfrag.mf ~= 0
  :off, :frag_off, :data_off, :data_len = lastfrag
  total_len = off + frag_off + data_off + data_len

  fragmented[id] = nil
  ip = IP4 :skb, :off
  ip.__len = -> total_len
  ip
