su = string.unpack

tcp: (off) =>
  spt, dpt, seq_n, ack_n, data_off, flags, window, cksum, urg_ptr, off = su ">H H I4 I4 B B H H H", @, off
  data_off = data_off & 0xf0 >> 2
  spt, dpt, seq_n, ack_n, data_off, flags, window, cksum, urg_ptr, off

