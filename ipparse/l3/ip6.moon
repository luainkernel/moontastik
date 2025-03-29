:format, pack: sp, unpack: su = string
:insert, :remove, :unpack = table
:toarray = require"ipparse.fun"
checksum: checksum, :pseudo_header = require "ipparse.l3.lib"

pack = =>
  if data = @data
    d = "#{data}"  -- Let the L4 payload recalculate its length
    data.checksum = 0
    d = "#{data}"
    data.checksum = checksum(pseudo_header(d, @src, @dst, @next_header) .. d)
    @payload_len = #d
  sp(">I4 I2 I1 I1 c16 c16", @vtf, @payload_len, @next_header, @hop_limit, @src, @dst) .. "#{@data or ''}"

_mt = __tostring: pack

parse = (off=1) =>
  vtf, payload_len, next_header, hop_limit, src, dst, data_off = su ">I4 I2 I1 I1 c16 c16", @, off
  setmetatable({
    :vtf, version: vtf >> 28, traffic_class: (vtf >> 20) & 0xff, flow_label: vtf & 0xfffff
    :payload_len
    :next_header
    :hop_limit
    :src, :dst
    :off, :data_off
  }, _mt), data_off

new = =>
  @vtf or= ((@version << 28) | (@traffic_class << 20) | @flow_label)
  setmetatable @, _mt

parse_ip6 = =>
  address = toarray @gmatch"([^:]*):?"
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


:parse, :new, :ip62s, :s2ip6, :net62s, :s2net6
