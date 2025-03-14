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


format: sf, pack: sp, rep: sr, unpack: su = string
unpack: tu = table

parse_ip6 = =>
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
  address

ip4 = => sp "BBBB", @match"(%d+)%.(%d+)%.(%d+)%.(%d+)"

ip6 = => sp ">HHHH HHHH", tu parse_ip6 @

net4 = =>
  b1, b2, b3, b4, mask = @match"(%d+)%.(%d+)%.(%d+)%.(%d+)/?(%d+)"
  sp "B BBBB", (tonumber mask or 32), tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4)

net6 = =>
  @, mask = @match"([^/]*)/?([^/]*)$"
  mask = tonumber(mask) or 128
  sp ">B HHHH HHHH", (tonumber mask or 128), tu parse_ip6 @

net = => @match":" and net6(@) or net4 @

contains = (subnet) =>
  return false if #@ ~= #subnet
  nmask = su "B", @
  smask = su "B", subnet
  return false if nmask > smask
  fmt, shft = "c#{nmask >> 3}", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, subnet, 2
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

contains_ip = (ip) =>
  return false if #@ ~= #ip+1
  nmask = su "B", @
  fmt, shft = "c#{nmask >> 3}", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, ip
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

format_ip4 = =>
  sf "%d.%d.%d.%d", su "BBBB", @

format_ip6 = =>
  sf "%x:%x:%x:%x:%x:%x:%x:%x", su ">HHHH HHHH", @

format_net4 = =>
  m, a, b, c, d = su "BBBBB", @
  sf "%d.%d.%d.%d/%d", a, b, c, d, m

format_net6 = =>
  m, a, b, c, d, e, f, g, h = su ">B HHHH HHHH", @
  sf "%x:%x:%x:%x:%x:%x:%x:%x/%d", a, b, c, d, e, f, g, h, m

ip = => @match":" and ip6(@) or ip4(@)

format_ip = => #@ == 16 and format_ip6(@) or format_ip4(@)

format_net = => #@ == 17 and format_net6(@) or format_net4(@)

:Net, :Net4, :Net6, :ip, :ip4, :ip6, :net, :net4, :net6, :contains, :contains_ip, :format_ip4, :format_ip6, :format_ip, :format_net

