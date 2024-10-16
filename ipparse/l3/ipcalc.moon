#!/usr/bin/env moon

concat, insert, remove = table.concat, table.insert, table.remove

map = (f) =>
  t = {}
  for i = 1, #@
    t[i] = f @[i], i
  t


reduce = (f) =>
  x = @[1]
  for i = 2, #@
    x = f x, @[i]
  x

local Net, Net4, Net6

Net4 = do
  __tostring = => concat([@[i] for i = 1, 4], ".") .. "/#{@mask}"
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
    bits = reduce map(
      [ tonumber n for n in @gmatch"[^%.]+" ]
      (i) => @ << 8*(4-i)
    ), (a, b) -> a + b
    bits = bits >> (32-mask) << (32-mask)
    setmetatable {:bits, :mask, v: 4}, mt


Net6 = do  -- 128 bits and IPv6 representation make it a bit more complex
  __repr = =>
    s = concat ["%x"\format(@[i]) for i = 1, 8], ":"
    for n = 8, 1, -1
      zeros = ":" .. concat ["0" for i = 1, n], ":"
      s, r = s\gsub zeros, "::", 1
      if r > 0
        s = s\gsub(":::*", "::")\gsub("^0::", "::")\gsub "^::0$", "::"
        break
    "#{s}/#{@mask}"
  mt =
    __index: (k) =>
      @bits[(k-1)//4+1] >> 16*((8-k)%4) & (1<<16)-1
    __le: (o) =>
      @ = Net(@) if type(@) == "string"
      o = Net(o) if type(o) == "string"
      (
        o.v == @v and o.mask <= @mask and
        (
          o.mask >= 64 and @bits[1] == o.bits[1] or
          o.mask < 64 and (@bits[1] >> (64-o.mask) << (64-o.mask)) == o.bits[1]
        ) and
        (@bits[2] >> (128-o.mask) << (128-o.mask)) == o.bits[2]
      )
    __tostring: __repr, :__repr
  Net6 = =>
    @, mask = @match"([^/]*)/?([^/]*)$"
    mask = tonumber(mask) or 128
    address = [h for h in @gmatch"([^:]*):?"]
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
        i += 1
    bits = {}
    for i = 1, #address
      k = (i-1) // 4 + 1
      bits[k] or= 0
      bits[k] += address[i] << 16*((8-i)%4)
    if mask < 64
      bits[1] = bits[1] >> (64-mask) << (64-mask)
    bits[2] = bits[2] >> (128-mask) << (128-mask)
    setmetatable {:bits, :mask, v: 6}, mt


Net = => @match":" and Net6(@) or Net4(@)


:Net, :Net4, :Net6

