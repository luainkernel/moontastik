:subclass, :Packet = require"ipparse"

subclass Packet, {
  __name: "UDP"

  protocol_type: 0x11

  _get_sport: => @short 0

  _get_dport: => @short 2

  _get_length: => @short 4

  _get_checksum: => @short 6

  data_off: 8
}
