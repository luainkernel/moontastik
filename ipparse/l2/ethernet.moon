subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet
range = require"ipparse.fun".range
concat = table.concat

subclass Packet, {
  __name: "Ethernet"

  get_mac_at: (off) => concat range(off, off+5)\map((i) -> "%x"\format @byte i)\toarray!, ":"

  _get_dst: => @get_mac_at 0

  _get_src: => @get_mac_at 6

  _get_length: => @short 12

  data_off: 14
}

