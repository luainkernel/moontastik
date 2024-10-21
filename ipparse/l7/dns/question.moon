subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet
map = require"ipparse.fun".map
concat = table.concat

subclass Packet, {
  __name: "DNSQuestion"

  _get_labels_offsets: =>
    offsets = {}
    pos = 0
    for _ = 1, 1000
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
    offs = @labels_offsets
    map(offs, (lbl) ->
      o, len, ptr = lbl[1], lbl[2], lbl[3]
      if len == 0
        for i = 1, #offs
          _lbl = offs[i]
          _o, _len = _lbl[1], _lbl[2]
          if _o == ptr
            o, len = _o, _len
            break
      @str o, len
    )\toarray!

  _get_qtype_offset: =>
    offs = @labels_offsets
    last = offs[#offs]
    last[1] + last[2] + 1

  _get_qtype: => @short @qtype_offset

  _get_qclass: => @short @qtype_offset+2

  _get_qname: => concat @labels, "."

  _get_length: => @qtype_offset + 4
}

