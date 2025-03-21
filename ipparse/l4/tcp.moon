su = string.unpack
unpack = table.unpack

FIN, SYN, RST, PSH, ACK, URG = unpack [ 1 << (i-1) for i = 1, 6 ]

{
  flags: {:FIN, :SYN, :RST, :PSH, :ACK, :URG}
  tcp: (off=0) =>
    spt, dpt, seq_n, ack_n, header_len, flags, window, checksum, urg_ptr, _off = su ">H H I4 I4 B B H H H", @, off
    header_len = (header_len & 0xf0) >> 2
    {
      :spt, :dpt, :seq_n, :ack_n
      :off, :header_len, data_off: off+header_len
      :flags, :window, :checksum, :urg_ptr
      urg: flags & URG ~= 0
      ack: flags & ACK ~= 0
      psh: flags & PSH ~= 0
      rst: flags & RST ~= 0
      syn: flags & SYN ~= 0
      fin: flags & FIN ~= 0
    }, _off
}
