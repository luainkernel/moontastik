#!/usr/bin/env moon

concat, insert, remove = table.concat, table.insert, table.remove
range, wrap = do
  _ = require"ipparse.fun"
  _.range, _.wrap

local Net, Net4, Net6

Net4 = do
  ip4 = => concat range(4)\map((i) -> @[i])\toarray!, "."
  __tostring = => ip4(@) .. "/#{@mask}"
  mt =
    __index: (k) => @bits >> 8*(4-k) & (1<<8)-1
    __le: (o) =>
      @ = Net(@) if type(@) == "string"
      o = Net(o) if type(o) == "string"
      o.v == @v and o.mask <= @mask and (@bits >> (32-o.mask) << (32-o.mask)) == o.bits
    :__tostring, __repr: __tostring
  =>
    @, mask = @match"([^/]*)/?([^/]*)$"
    mask = tonumber(mask) or 32
    bits = wrap(@gmatch"[^%.]+")\imap((i) => tonumber(@) << 8*(4-i))\reduce (a, b) -> a + b
    bits = bits >> (32-mask) << (32-mask)
    setmetatable {:bits, :mask, v: 4, ip: ip4}, mt


Net6 = do  -- 128 bits and IPv6 representation make it a bit more complex
  ip6 = =>
    s = concat range(8)\map((i) -> "%x"\format(@[i]))\toarray!, ":"
    for n = 8, 1, -1
      zeros = ":" .. concat range(n)\map(-> "0")\toarray!, ":"
      s, r = s\gsub zeros, "::", 1
      if r > 0
        s = s\gsub(":::*", "::")\gsub("^0::", "::")\gsub "^::0$", "::"
        break
    s
  __repr = => ip6(@) .. "/#{@mask}"
  mt =
    __index: (k) =>
      @bits[(k-1)//4+1] >> 16*((8-k)%4) & (1<<16)-1
    __le: (o) =>
      @ = Net(@) if type(@) == "string"
      o = Net(o) if type(o) == "string"
      return false if o.v ~= @v or o.mask > @mask
      return false if o.mask >= 64 and @bits[1] ~= o.bits[1]
      return false if o.mask < 64 and (@bits[1] >> (64-o.mask) << (64-o.mask)) ~= o.bits[1]
      (@bits[2] >> (128-o.mask) << (128-o.mask)) == o.bits[2]
    __tostring: __repr, :__repr, ip: ip6
  =>
    @, mask = @match"([^/]*)/?([^/]*)$"
    mask = tonumber(mask) or 128
    address = wrap(@gmatch"([^:]*):?")\toarray!
    zeros = 9 - #address
    for i = 1, 8
      part = address[i]
      if part == "" and zeros
        for _ = 1, zeros
          insert address, i, 0
          i += 1
        zeros = 1
        remove address, i
      else
        address[i] = type(part) == "string" and tonumber(part, 16) or part
    bits = {}
    for i = 1, #address
      k = (i-1) // 4 + 1
      bits[k] or= 0
      bits[k] += address[i] << 16*((8-i)%4)
    if mask < 64
      bits[1] = bits[1] >> (64-mask) << (64-mask)
    bits[2] = bits[2] >> (128-mask) << (128-mask)
    setmetatable {:bits, :mask, v: 6, ip: ip6}, mt


Net = => @match":" and Net6(@) or Net4(@)


:Net, :Net4, :Net6

