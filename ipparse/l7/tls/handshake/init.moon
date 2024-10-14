:subclass, :Packet = require"ipparse"


subclass Packet, {
  __name: "TLSHandshake"

  record_type: 0x16

  _get_type: => @byte 0

  _get_length: => @byte(1) << 16 | @short 2

  data_off: 4
}