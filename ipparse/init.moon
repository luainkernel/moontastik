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
su = string.unpack


local Object
Object =
  __name: "Object"
  new: (obj) =>
    local _mt
    _mt =
      __call: (obj, ...) =>
        obj\new ... if obj.new
        setmetatable obj, __index: @
      __len: @ and @__len
    obj[k] or= v for k, v in pairs @
    obj._parent = @
    setmetatable obj, _mt
subclass = Object.new
subclass {}, Object


Packet = subclass Object, {
  __name: "Packet"
  __len: => #@_data - @data_off
  data_off: 0

  bit: (offset, n = 1) =>
    (su("B", @_data, @off+offset+1) >> (8-n)) & 1

  nibble: (offset, half = 1) =>
    b = su "B", @_data, @off+offset+1
    half == 1 and b >> 4 or b & 0xf

  byte: (offset) =>
    su "B", @_data, @off+offset+1

  short: (offset) =>
    ntoh16 su "I2", @_data, @off+offset+1

  word: (offset) =>
    ntoh32 su "I4", @_data, @off+offset+1

  str: (offset=0, length) =>
    off = @off + offset
    frag = ""
    if off + length > #@_data
      length = nil
      log"Incomplete data. Fragmented packet?"
    @_data\sub(off+1, off+length) .. frag

  is_empty: => @off >= #@_data

  -- Each subclass has to define data_off
  payload: => _container: @, _data: @_data, off: @off + @data_off

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

if DEBUG
  Packet.bit = (offset, n = 1) =>
    ok, ret = pcall string.unpack, "B", @_data, @off+offset+1
    ((ret >> (8-n)) & 1) if ok else log @__name, "bit", ret, "#{@off} #{offset} #{#@_data}"
  Packet.nibble = (offset, half = 1) =>
    ok, ret = pcall string.unpack, "B", @_data, @off+offset+1
    (half == 1 and ret >> 4 or ret & 0xf) if ok else log @__name, "nibble", "#{@off} #{offset} #{#@_data}"
  Packet.byte = (offset) =>
    ok, ret = pcall string.unpack, "B", @_data, @off+offset+1
    ret if ok else log @__name, "byte", ret, @off, offset, #@_data
  Packet.short = (offset) =>
    ok, ret = pcall string.unpack, "I2", @_data, @off+offset+1
    ntoh16(ret) if ok else log @__name, "short", ret, @off, offset, #@_data
  Packet.word = (offset) =>
    ok, ret = pcall string.unpack, "I4", @_data, @off+offset+1
    ntoh32(ret) if ok else log @__name, "word", ret, @off, offset, #@_data
  Packet.str = (offset=0, length) =>
    off = @off + offset
    frag = ""
    if off + length > #@_data
      length = nil
      log"Incomplete data. Fragmented packet?"
    ok, ret = pcall string.sub, @_data, off+1, off+length
    (ret .. frag) if ok else log @__name, "str", ret, "#{@off} #{offset} #{length} #{#@_data}"


format: sf, rep: sr, unpack: su = string
hexdump = (off=1, f="%.2x") =>
  n = #@ - off
  n = n < 128 and n or 127
  mask = sr "I1", n
  sf sr("#{f} ", n), su mask, @, off

:Object, :subclass, :Packet, :hexdump

