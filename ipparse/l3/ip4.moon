:subclass = require"ipparse"
IP = require"ipparse.l3.ip"
:concat = table

subclass IP, {
  __name: "IP4"

  get_ip_at: (off) => concat [ "%d"\format(@byte i) for i = off, off+3 ], "."

  is_fragment: => @mf ~= 0 or @fragmentation_off ~= 0

  _get_ihl: => @nibble 0, 2

  _get_tos: => @byte 1

  _get_length: => @short 2

  _get_id: => @short 4

  _get_reserved: => @bit 6, 1

  _get_df: => @bit 6, 2

  _get_mf: => @bit 6, 3

  _get_fragmentation_off: => (@bit(6, 4) << 12) | (@nibble(6, 2) << 8) | @byte(7)

  _get_ttl: => @byte 8

  _get_protocol: => @byte 9

  _get_header_checksum: => @short 10

  _get_src: => @get_ip_at 12

  _get_dst: => @get_ip_at 16

  _get_data_off: => 4 * @ihl

  _get_data_len: => @length - @data_off
}
