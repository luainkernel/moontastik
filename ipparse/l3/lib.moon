pack: sp, unpack: su = string

pseudo_header = (src, dst, protocol) =>
  src .. dst .. sp ">BBH", 0, protocol, #@

checksum = =>
  cksm = 0
  @ ..= "\0" if #@ & 1 == 1
  for i = 1, #@, 2
    cksm += su ">H", @, i
  -- Handle carry-over
  while true
    carry = cksm >> 16
    break if carry == 0
    cksm = (cksm & 0xFFFF) + carry
  -- Return the one's complement of the checksum
  ~cksm & 0xFFFF

:checksum, :pseudo_header