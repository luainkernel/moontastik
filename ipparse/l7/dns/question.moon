:subclass, :Packet = require"ipparse"
:concat = table

subclass Packet, {
  __name: "DNSQuestion"

  _get_labels_offsets: =>
    offsets = {}
    pos = 0
    for i = 1, 1000
      size = @byte pos
      break if size == 0
      pos += 1
      if size & 0xC0 == 0
        offsets[#offsets+1] = {pos, size}
      else
        off = ((size & 0x3F) << 8) + @byte pos
        offsets[#offsets+1] = {off+1, @byte off}
        break
      pos += size
    offsets

  _get_labels: =>
    labels = {}
    offs = @labels_offsets
    for {o, len, ptr} in *offs
      if len == 0
        for {_o, _len} in *offs
          if _o == ptr
            o, len = _o, _len
            break
      labels[#labels+1] = @str o, len
    labels

  _get_qtype_offset: =>
    offs = @labels_offsets
    {pos, size} = offs[#offs]
    pos + size + 1

  _get_qtype: => @short @qtype_offset

  _get_qclass: => @short @qtype_offset+2

  _get_qname: => concat @labels, "."

  _get_length: => @qtype_offset + 4
}

