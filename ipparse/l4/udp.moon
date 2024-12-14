su = string.unpack

udp: (off) => su ">H H H H", @, off  -- spt, dpt, len, checksum, off

