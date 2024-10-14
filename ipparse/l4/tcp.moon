:subclass, :Packet = require"ipparse"

subclass Packet, {
  __name: "TCP"

  protocol_type: 0x06

  _get_sport: => @short 0

  _get_dport: => @short 2

  _get_sequence_number: => @word 4

  _get_acknowledgment_number: => @word 8

  _get_data_off: => 4 * @nibble 12

  _get_URG: => @bit 13, 3

  _get_ACK: => @bit 13, 4

  _get_PSH: => @bit 13, 5

  _get_RST: => @bit 13, 6

  _get_SYN: => @bit 13, 7

  _get_FIN: => @bit 13, 8

  _get_window: => @short 14

  _get_checksum: => @short 16

  _get_urgent_pointer: => @short 18
}
