:subclass, :Packet = require"ipparse"
:concat = table

subclass Packet, {
  __name: "DNSRessourceRecord"

  _get_labels_offsets: =>
    offsets = {}
    pos = 0
    for i = 1, 1000
      size = @byte pos
      break if size == 0
      pos += 1
      offsets[#offsets+1] = {pos, (size & 0xC0 and 0 or size), size & 0x3F}
      break if size & 0xC0
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

  _get_type_offset: =>
    offs = @labels_offsets
    {pos, size} = offs[#offs]
    pos + size + 1

  _get_type: => @short @type_offset

  _get_class: => @short @type_offset+2

  _get_ttl: => @word @type_offset+4

  _get_rdlength: => @short @type_offset+8

  _get_rdata: => [ @byte(@type_offset+10+off) for off = 0, @rdlength-1 ]

  _get_name: => concat @labels, "."

  _get_length: => @type_offset + 10 + @rdlength
}

