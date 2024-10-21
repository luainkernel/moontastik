subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet

bidirectional = =>
  @[v] = k for k, v in pairs @
  @


subclass Packet, {
  __name: "IP"

  _get_version: => @nibble 0

  protocols: bidirectional {
    TCP:    0x06
    UDP:    0x11
    GRE:    0x2F
    ESP:    0x32
    ICMPv6: 0x3A
    OSPF:   0x59
  }
}
