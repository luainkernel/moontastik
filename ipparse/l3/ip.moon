:subclass, :Packet = require"ipparse"

[[
protocols: {
    TCP:    0x06
    UDP:    0x11
    GRE:    0x2F
    ESP:    0x32
    ICMPv6: 0x3A
    OSPF:   0x59
  }
]]

subclass Packet, {
  __name: "IP"

  _get_version: => @nibble 0
}
