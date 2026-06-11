--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Stateful IPv4 fragment reassembly (Lunatik only: relies on the `data` module).
-- Fragments are accumulated per flow (src, dst, protocol, id); the reassembled
-- packet is returned once the last fragment (MF=0) covering the flow arrives.
-- Pending flows are bounded: when more than `MAX_PENDING` flows are in flight,
-- the oldest one is dropped so a flood of never-completed fragments cannot
-- exhaust kernel memory.
-- @module l3.fragmented_ip4

IP4 = require"ipparse.l3.ip4"
new: data_new = require"data"
:sort = table
{:lshift} = require"ipparse.lib.bit_compat"

MAX_PENDING = 64

fragmented = {}
pending = 0
order, order_first, order_last = {}, 1, 0

-- Drop the oldest still-pending flow (entries already completed are skipped).
evict_oldest = ->
  while order_first <= order_last
    key = order[order_first]
    order[order_first] = nil
    order_first += 1
    if fragmented[key]
      fragmented[key] = nil
      pending -= 1
      return

collect: (_skb) =>
  :id, :off, :data_off, :data_len, :mf = @
  key = "#{@src}#{@dst}#{@protocol}#{id}"
  fragments = fragmented[key]
  unless fragments
    evict_oldest! if pending >= MAX_PENDING
    fragments = {}
    fragmented[key] = fragments
    pending += 1
    order_last += 1
    order[order_last] = key
  frag_off = lshift(@fragmentation_off, 3)
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

  fragmented[key] = nil
  pending -= 1
  ip = IP4.parse skb
  ip, @
