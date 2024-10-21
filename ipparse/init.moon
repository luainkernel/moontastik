DEBUG = false

if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

concat = table.concat
log = (...) -> print "IPPARSE: " .. concat {...}, "\t"
ntoh16, ntoh32 = do
  _ = require"linux"
  _.ntoh16, _.ntoh32
range = require"ipparse.fun".range


Object = {
  __name: "Object"
  new: (cls, obj) ->
    cls = nil if cls == obj
    setmetatable obj, {
      __index: (k) =>
        if getter = rawget(@, "_get_#{k}") or cls and cls["_get_#{k}"]
          v = getter @
          @[k] = v
          v
        elseif cls
          cls[k]
      __call: (...) => obj\new ...
      __len: => @__len!
    }
}
Object.new Object, Object
subclass = Object.new


Packet = subclass Object, {
  __name: "Packet"
  __len: => #@skb
  new: (obj) =>
    assert obj.skb, "I need a skb to parse"
    obj.off or= 0
    Object.new @, obj

  bit: (offset, n = 1) =>
    if DEBUG
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ((ret >> (8-n)) & 1) if ok else log @__name, "bit", ret, "#{@off} #{offset} #{#@skb}"
    else
      (@skb\getbyte(@off+offset) >> (8-n)) & 1

  nibble: (offset, half = 1) =>
    if DEBUG
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      (half == 1 and ret >> 4 or ret & 0xf) if ok else log @__name, "nibble", "#{@off} #{offset} #{#@skb}"
    else
      b = @skb\getbyte @off+offset
      half == 1 and b >> 4 or b & 0xf

  byte: (offset) =>
    if DEBUG
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ret if ok else log @__name, "byte", ret, "#{@off} #{offset} #{#@skb}"
    else
      @skb\getbyte @off+offset

  short: (offset) =>
    if DEBUG
      ok, ret = pcall @skb.getuint16, @skb, @off+offset
      ntoh16(ret) if ok else log @__name, "short", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh16 @skb\getuint16 @off+offset

  word: (offset) =>
    if DEBUG
      ok, ret = pcall @skb.getuint32, @skb, @off+offset
      ntoh32(ret) if ok else log @__name, "word", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh32 @skb\getuint32 @off+offset

  str: (offset=0, length=#@skb-@off) =>
    off = @off + offset
    frag = ""
    if off + length > #@skb
      length = #@skb - off
      log"Incomplete data. Fragmented packet?"
    if DEBUG
      ok, ret = pcall @skb.getstring, @skb, @off+offset, length
      (ret .. frag) if ok else log @__name, "str", ret, "#{@off} #{offset} #{length} #{#@skb}"
    else
      @skb\getstring(@off+offset, length) .. frag

  is_empty: => @off >= #@skb

  -- Each subclass has to define data_off or _get_data_off
  _get_data: => skb: @skb, off: @off + @data_off

  hexdump: =>
    hex, txt = {}, {}
    mx = #@ - @off
    char = string.char
    for i = 1, mx
      c = @byte(i-1)
      hex[i] = "%.02x"\format c
      txt[i] = c > 32 and c < 127 and char(c) or '.'
    range(1, #hex, 8)\map (i) ->
      m = i+7
      concat({
        concat range(i, m)\map(=> hex[@] or "  ")\toarray!, " "
        concat range(i, m)\map(=> txt[@] or " ")\toarray!
      }, "  ") .. "  %.03x"\format m
}


:Object, :subclass, :Packet

