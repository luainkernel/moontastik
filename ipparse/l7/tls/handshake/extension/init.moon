pack: sp, unpack: su = string

pack = =>
  sp ">H s2", @type, @data

_mt =
  __tostring: pack

parse = (off=1) =>
  _type, data, _off = su ">H s2", @, off
  setmetatable({type: _type, :data}, _mt), _off

:parse, :pack
