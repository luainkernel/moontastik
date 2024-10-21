subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet
map, range = do
  _ = require"ipparse.fun"
  _.map, _.range
concat = table.concat

subclass Packet, {
  __name: "DNSRessourceRecord"

  _get_labels_offsets: =>
    offsets = {}
    pos = 0
    for _ = 1, 1000
      size = @byte pos
      break if size == 0
      pos += 1
      offsets[#offsets+1] = {pos, (size & 0xC0 and 0 or size), size & 0x3F}
      break if size & 0xC0
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

  _get_type_offset: =>
    offs = @labels_offsets
    last = offs[#offs]
    last[1] + last[2] + 1

  _get_type: => @short @type_offset

  _get_class: => @short @type_offset+2

  _get_ttl: => @word @type_offset+4

  _get_rdlength: => @short @type_offset+8

  _get_rdata: => range(0, @rdlength-1)\map((off) -> @byte @type_offset+10+off)\toarray!

  _get_name: => concat @labels, "."

  _get_length: => @type_offset + 10 + @rdlength
}

