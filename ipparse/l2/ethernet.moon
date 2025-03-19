:bidirectional = require"ipparse.fun"
:byte, :format, pack: sp, unpack: su = string
:unpack = table
mac_str = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
mac = "BBBBBB"

ethernet = (off=0) =>  -- Accepts data string; returns ethernet header informations
  dst, src, protocol, data_off = su "c6 c6 >H", @, off
  {:dst, :src, :protocol, :off, :data_off}, data_off

mac2s = =>  -- Accepts data string; returns mac address as readable string
  format mac_str, su mac, @

s2mac = =>  -- Accepts readable string; returns mac address as data string
  sp mac, unpack [tonumber(s, 16) for s in @gmatch"[^:]+"]

proto =  -- Protocol numbers as found in the ethernet header
  IP6: 0x86DD
  IP4: 0x800
proto = bidirectional proto

:ethernet, :proto, :mac2s, :s2mac
