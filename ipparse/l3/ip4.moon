subclass = require"ipparse".subclass
IP = require"ipparse.l3.ip"
:ntoh16 = require"linux"
concat = table.concat
su = string.unpack

get_ip_at = (off) ->
  off += 1
  => su "c4", @_data, off

subclass IP, {
  __name: "IP4"

  new: =>
    @data_off = 4 * @ihl!

  is_fragment: => @mf ~= 0 or @fragmentation_off ~= 0

  ihl: => su("B", @_data, @off+1) & 0x0f

  tos: => @byte 1

  length: => @short 2

  id: => @short 4

  reserved: => @bit 6, 1

  df: => @bit 6, 2

  mf: => @bit 6, 3

  fragmentation_off: => (@bit(6, 4) << 12) | (@nibble(6, 2) << 8) | @byte(7)

  ttl: => @byte 8

  protocol: => @byte 9

  header_checksum: => @short 10

  src: get_ip_at 12

  dst: get_ip_at 16


  data_len: => @length - @data_off

  __len: => @length
}

ip4 = (off) =>
  v_ihl, tos, len, id, ff, ttl, protocol, header_checksum, src, dst = su "B B I2 I2 B B I2 c4 c4", @, off
  version, ihl = v_ihl >> 4, v_ihl & 0x0f
  version, ihl, tos, ntoh16(len), ntoh16(id), ff, ttl, protocol, ntoh16(header_checksum), src, dst, off+4*ihl

:ip4
