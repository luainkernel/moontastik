pack: sp, unpack: su, :sub, :upper = string
:bidirectional = require"ipparse.fun"

flags = bidirectional {
  FIN: 0x01
  SYN: 0x02
  RST: 0x04
  PSH: 0x08
  ACK: 0x10
  URG: 0x20
}
:FIN, :SYN, :RST, :PSH, :ACK, :URG = flags

pack = =>
  sp(">H H I4 I4 B B H H H", @spt, @dpt, @seq_n, @ack_n, @header_len, @flags, @window, @checksum, @urg_ptr) .. @options .. "#{@data or ''}"

_mt =
  __tostring: pack
  __index: (k) =>
    if flag = type(k) == "string" and upper k
      if flag = flags[flag]
        @flags & flag ~= 0
  __newindex: (k, v) =>
    if flag = type(k) == "string" and upper k
      if flag = flags[flag]
        if v then @flags |= flag else @flags &= ~flag
        return
    rawset @, k, v

parse = (off=1) =>
  spt, dpt, seq_n, ack_n, header_len, _flags, window, checksum, urg_ptr, _off = su ">H H I4 I4 B B H H H", @, off
  data_off = off + ((header_len & 0xf0) >> 2)
  options = sub @, _off, data_off-1
  setmetatable({
    :spt, :dpt, :seq_n, :ack_n
    :off, :header_len, :data_off
    flags: _flags, :window, :checksum, :urg_ptr
    :options
  }, _mt), _off

new = =>
  @flags or= ((@urg and URG) | (@ack and ACK) | (@psh and PSH) | (@rst and RST) | (@syn and SYN) | (@fin and FIN))
  setmetatable @, _mt

:flags, :parse, :new, :pack
