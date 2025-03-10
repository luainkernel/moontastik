subclass = require"ipparse".subclass
IP = require"ipparse.l3.ip"
Net6 = require"ipparse.l3.ipcalc".Net6
range = require"ipparse.fun".range
:concat = table

subclass IP, {
  __name: "IP6"

  get_ip_at: (off) => Net6(concat range(off, off+14, 2)\map((i) -> "%x"\format @short i)\toarray!, ":")\ip!

  is_fragment: ->  -- TODO: IPv6 defragmentation

  _get_length: => @data_off + @short 4

  _get_next_header: => @byte 6

  _get_protocol: => @next_header

  _get_src: => @get_ip_at 7

  _get_dst: => @get_ip_at 24

  data_off: 40
}

ip6 = (off) =>
  vtf, payload_len, next_header, hop_limit, src, dst, off = su "c4 I2 I1 I1 c16 c16", @, off
  vtf, ntoh16(payload_len), next_header, hop_limit, src, dst, off

:ip6
