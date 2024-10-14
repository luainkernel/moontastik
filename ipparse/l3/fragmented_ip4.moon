:subclass, :Object = require"ipparse"
IP4 = require"ipparse.l3.ip4"
new: data_new = require"data"
:insert = table


subclass IP4, {
  new: (obj={}) =>
    obj.off or= 0
    Object.new @, obj

  insert: (fragment) =>
    if prec = @[1]
      assert fragment.id == prec.id
      for i = 1, #@
        if fragment.fragmentation_off < @[i].fragmentation_off
          insert @, i, fragment
          return @
      @[#@+1] = fragment
      return @
    @[1] = fragment
    @

  is_complete: =>
    return false if @[#@].mf ~= 0
    for i = 2, #@
      this, prec = @[i], @[i-1]
      return false if (this.fragmentation_off << 3) ~= (prec.fragmentation_off << 3) + prec.data_len
    true

  _get_skb: =>
    assert @is_complete!, "Can't access payload of incomplete fragmented packet"
    :fragmentation_off, :data_len = @[#@]
    skb = data_new((fragmentation_off << 3) + data_len)
    off = 0
    skb: _skb = @[1]
    for j = 0, #_skb - 1
      skb\setbyte off, _skb\getbyte j
      off += 1
    for i = 2, #@
      {skb: _skb, :data_off} = @[i]
      for j = 0, #_skb - 1
        skb\setbyte off, _skb\getbyte(data_off + j)
        off += 1
    skb
}