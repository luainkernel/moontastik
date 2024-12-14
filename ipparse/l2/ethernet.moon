:subclass, :Packet = require"ipparse"
:bidirectional = require"ipparse.fun"
format: sf, unpack: su = string

ethernet = (off=0) =>
  -- Returns destination, source, protocol, payload offset
  dst, src, protocol, off = su "c6 c6 >H", @, off
  dst, src, protocol, off

format_mac = =>
  sf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", su "BBBBBB", @

proto =
  IP6: 0x86DD
  IP4: 0x800
proto = bidirectional proto

:ethernet, :proto, :format_mac
