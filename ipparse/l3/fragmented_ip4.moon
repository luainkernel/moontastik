IP4 = require"ipparse.l3.ip4"
new: data_new = require"data"
:sort = table
:max = math

fragmented = {}

collect: =>
  id = @id
  fragments = fragmented[id] or {}
  fragmented[id] = fragments
  skb: _skb, :off, :data_off, :data_len, :fragmentation_off, :mf = @
  frag_off = fragmentation_off << 3
  total_len = off + frag_off + data_off + data_len
  -- 64KB is the theoretical maximum, 10KB a reasonable max len default
  max_len = total_len > 10240 and 65535 or 10240
  return nil, "Invalid size" if max_len > 65535
  skb = fragments.skb
  if skb
    if #skb < max_len  -- Handle the case of a very big jumbo frame
      tmp = data_new max_len
      tmp\setbyte i, skb\getbyte(i) for i = 0, #skb-1
      skb = tmp
  else
    skb = data_new max_len
  fragments.skb = skb
  if frag_off == 0
    skb\setbyte i, _skb\getbyte(i) for i = 0, off + data_off + data_len - 1
  else
    offset = off + data_off
    skb\setbyte (frag_off + i), _skb\getbyte(i) for i = offset, offset + data_len - 1
  fragments[#fragments+1] = {:frag_off, :off, :data_off, :data_len, :mf}
  sort fragments, (a, b) -> a.frag_off < b.frag_off
  lastfrag = fragments[#fragments]
  return if lastfrag.mf ~= 0
  :off, :frag_off, :data_off, :data_len = lastfrag
  total_len = off + frag_off + data_off + data_len

  fragmented[id] = nil
  ip = IP4 :skb, :off
  ip.__len = => total_len
  ip

