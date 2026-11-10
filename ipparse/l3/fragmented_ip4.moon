--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Stateful IPv4 fragment reassembly (pure Lua strings).
-- Fragments are accumulated per flow (src, dst, protocol, id) and the
-- reassembled payload is returned once every byte from offset 0 up to the end
-- of the last fragment (MF=0) has been received.
-- Pending flows are bounded: when more than `MAX_PENDING` flows are in flight,
-- the oldest one is dropped so a flood of never-completed fragments cannot
-- exhaust memory. Each flow also keeps at most 256 fragments.
-- This module only uses Lua strings, so it works both in user space and in the
-- Lunatik kernel.
-- @module l3.fragmented_ip4

:sort = table
require "ipparse"  -- kernel stack budget: load the shared base first (see AGENTS.md)
pack: sp = require"ipparse.lib.pack_compat"
{:band, :lshift} = require"ipparse.lib.bit_compat"

--- Maximum number of pending (incomplete) flows kept at once.
MAX_PENDING = 64

--- Maximum number of fragments remembered per flow.
MAX_FRAGMENTS = 256

fragmented = {}
pending = 0
seq = 0
order, order_first, order_last = {}, 1, 0

-- Drop the oldest still-pending flow. Queue entries are indexed by flow
-- sequence number; an entry whose flow is gone or has been superseded by a new
-- flow with the same key (different `seq`) is stale and simply skipped.
evict_oldest = ->
  while order_first <= order_last
    current = order_first
    key = order[current]
    order[current] = nil
    order_first += 1
    if key != nil and fragmented[key] and fragmented[key].seq == current
      fragmented[key] = nil
      pending -= 1
      return

-- Drop a flow by key, keeping the pending counter and queue consistent.
drop_flow = (key) ->
  if fragmented[key]
    order[fragmented[key].seq] = nil
    fragmented[key] = nil
    pending -= 1

-- Reassemble the chunks of a flow into a contiguous string, or return nil when
-- a gap remains. Overlapping fragments are truncated; the first gap stops the
-- walk. `total` is the expected reassembled length.
reassemble = (chunks, total) ->
  offsets = [off for off, _ in pairs chunks]
  sort offsets
  out = {}
  expected = 0
  for off in *offsets
    chunk = chunks[off]
    chunk_end = off + #chunk - 1
    continue if chunk_end < expected
    break if off > expected
    start_idx = expected > off and (expected - off + 1) or 1
    out[#out + 1] = chunk\sub start_idx
    expected = chunk_end + 1
  return nil if expected < total
  table.concat out

--- Collects an IPv4 fragment and returns the reassembled payload when complete.
-- @tparam table ip IPv4 header as returned by `ip4.parse`.
-- @tparam string pkt String containing the whole packet.
-- @treturn string|nil Reassembled payload, or `nil` while more fragments are needed.
-- @treturn table|nil The first fragment's header when reassembly completes.
-- @treturn string|nil Error message on invalid input.
collect = (ip, pkt) ->
  header_len = ip.data_off - ip.off
  return nil, "truncated packet" if ip.total_len < header_len
  last = ip.off + ip.total_len - 1
  return nil, "truncated packet" if last > #pkt
  payload = pkt\sub ip.data_off, last
  frag_off = lshift(band(ip.ff, 0x1fff), 3)
  mf = band(ip.ff, 0x2000) != 0
  if frag_off == 0 and not mf
    return payload, ip

  key = sp ">c4 c4 B H", ip.src, ip.dst, ip.protocol, ip.id
  if frag_off + #payload > 65535
    drop_flow key
    return nil, "fragment exceeds 65535 bytes"
  if mf and (#payload % 8) != 0
    return nil, "invalid fragment length"

  state = fragmented[key]
  unless state
    evict_oldest! if pending >= MAX_PENDING
    seq += 1
    state = {chunks: {}, total: nil, first: nil, n: 0, seq: seq}
    fragmented[key] = state
    pending += 1
    order_last = seq
    order[seq] = key

  if not state.chunks[frag_off]
    if state.n >= MAX_FRAGMENTS
      drop_flow key
      return nil, "too many fragments"
    state.n += 1
  state.chunks[frag_off] = payload
  state.first = ip if frag_off == 0
  state.total = frag_off + #payload unless mf

  if state.total and state.first
    data = reassemble state.chunks, state.total
    if data
      first = state.first
      drop_flow key
      return data, first
  return nil

--- Clears all reassembly state.
reset = ->
  fragmented = {}
  pending = 0
  seq = 0
  order, order_first, order_last = {}, 1, 0

--- Returns the number of pending flows and live eviction-queue entries.
-- @treturn number Pending (incomplete) flow count.
-- @treturn number Number of non-nil entries in the eviction queue.
stats = ->
  queued = 0
  for _ in pairs order
    queued += 1
  pending, queued

{:collect, :reset, :stats, :MAX_PENDING}
