pack: sp, unpack: su = string

pack = =>
  @len = 8 + (@data and #"#{@data}" or 0)
  sp(">H H H H", @spt, @dpt, @len, @checksum) .. "#{@data or ''}"

_mt = __tostring: pack

parse = (off=1) =>  -- Accepts data string; returns UDP header infos
  spt, dpt, len, checksum, data_off = su ">H H H H", @, off
  setmetatable({:spt, :dpt, :len, :checksum, :off, :data_off}, _mt), data_off

new = =>
  setmetatable @, _mt


:parse, :new, :pack
