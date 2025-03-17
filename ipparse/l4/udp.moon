pack: sp, unpack: su = string

udp = (off) =>  -- Accepts data string; returns UDP header infos
  spt, dpt, len, checksum, data_off = su ">H H H H", @, off
  {:spt, :dpt, :len, :checksum, :data_off}, data_off

checksum = (ip) =>
  :protocol = ip
  len = #@
  -- Calculate the pseudo-header checksum
  data = ip.src .. ip.dst .. sp(">BBH", 0, protocol, len) .. @
  if #data & 1 == 1
    data = data.."\0"
  -- Calculate the checksum of the pseudo-header and the packet
  checksum = 0
  for i = 1, #data, 2
    word = su ">H", data, i
    checksum += word
  -- Handle carry-over
  while true
    carry = checksum >> 16
    break if carry == 0
    checksum = (checksum & 0xFFFF) + carry
  -- Return the one's complement of the checksum
  ~checksum & 0xFFFF

:checksum, :udp
