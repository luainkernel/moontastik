:subclass = require"ipparse"
IP = require"ipparse.l3.ip"
:concat = table

subclass IP, {
  __name: "IP6"

  get_ip_at: (off) => concat [ "%x"\format(@short i) for i = off, off+14, 2 ], ":"

  is_fragment: => false  -- TODO: IPv6 defragmentation

  _get_length: => @data_off + @short 4

  _get_next_header: => @byte 6

  _get_protocol: => @next_header

  _get_src: => @get_ip_at 8

  _get_dst: => @get_ip_at 24

  _get_data_off: => 40
}