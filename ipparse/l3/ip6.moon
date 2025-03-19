:format, pack: sp, unpack: su = string
:insert, :remove, :unpack = table
:range, :wrap = require"ipparse.fun"
:ntoh16 = require"linux"

ip6 = (off=0) =>
  vtf, payload_len, next_header, hop_limit, src, dst, data_off = su ">I4 I2 I1 I1 c16 c16", @, off
  {
    version: vtf >> 28, traffic_class: (vtf >> 20) & 0xff, flow_label: vtf & 0xfffff
    :payload_len
    :next_header
    :hop_limit
    :src, :dst
    :off, :data_off
  }, data_off

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

ip62s = =>  -- Accepts data string; returns IPv6 address as readable string
  format "%x:%x:%x:%x:%x:%x:%x:%x", su ">HHHH HHHH", @

s2ip6 = =>  -- Accepts readable string; returns IPv6 address as data string
  sp ">HHHH HHHH", unpack parse_ip6 @

net62s = =>  -- Accepts data string; returns IPv6 subnet as readable string
  m, a, b, c, d, e, f, g, h = su ">B HHHH HHHH", @
  format "%x:%x:%x:%x:%x:%x:%x:%x/%d", a, b, c, d, e, f, g, h, m

s2net6 = =>  -- Accepts readable string; returns IPv6 subnet as data string
  @, mask = @match"([^/]*)/?([^/]*)$"
  mask = tonumber(mask) or 128
  sp ">B HHHH HHHH", (tonumber mask or 128), unpack parse_ip6 @


:ip6, :ip62s, :s2ip6, :net62s, :s2net6
