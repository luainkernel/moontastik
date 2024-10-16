IP4 = require"ipparse.l3.ip4"
new: data_new = require"data"
:sort = table


fragmented = {}

collect: =>
  id = @id
  @data_len
  fragments = fragmented[id] or {}
  fragmented[id] = fragments
  skb: _skb, :off, :data_len, :data_off, :fragmentation_off, :mf = @
  skb = data_new #_skb
  skb\setbyte i, _skb\getbyte(i) for i = 0, #_skb-1
  fragments[#fragments+1] = {:skb, :off, :data_len, :data_off, :fragmentation_off, :mf}
  sort fragments, (a, b) -> a.fragmentation_off < b.fragmentation_off

  return if fragments[#fragments].mf ~= 0
  total_len = 0
  for f in *fragments
    return if total_len ~= (f.fragmentation_off << 3)
    total_len += f.data_len
  firstfrag = fragments[1]
  total_len += firstfrag.off + #firstfrag.skb - firstfrag.data_len

  skb = data_new total_len
  off = 0
  _skb = fragments[1].skb
  for j = 0, #_skb - 1
    skb\setbyte off, _skb\getbyte j
    off += 1
  for i = 2, #fragments
    {skb: _skb, :data_off} = fragments[i]
    for j = 0, #_skb - data_off - 1
      skb\setbyte off, _skb\getbyte(data_off + j)
      off += 1
  fragmented[id] = nil
  IP4 :skb, off: @off

