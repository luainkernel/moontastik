:bidirectional = require"ipparse.fun"
:format, pack: sp, unpack: su = string
:unpack = table
mac_str = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
mac = "BBBBBB"

pack = => sp("c6 c6 >H", @dst, @src, @protocol) .. "#{@data or ''}"

_mt = __tostring: pack

parse = (off=1) =>  -- Accepts data string; returns ethernet header informations
  dst, src, protocol, data_off = su "c6 c6 >H", @, off
  setmetatable({:dst, :src, :protocol, :off, :data_off}, _mt), data_off

new = =>
  setmetatable @, _mt

mac2s = =>  -- Accepts data string; returns mac address as readable string
  format mac_str, su mac, @

s2mac = =>  -- Accepts readable string; returns mac address as data string
  sp mac, unpack [tonumber(s, 16) for s in @gmatch"[^:]+"]

proto =  -- Protocol numbers as found in the ethernet header
  IP6: 0x86DD
  IP4: 0x800
proto = bidirectional proto

:parse, :new, :pack, :proto, :mac2s, :s2mac
