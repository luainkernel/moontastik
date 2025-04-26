pack: sp, unpack: su = string

pack = =>
  sp ">H s2", @len, @name

_mt =
  __tostring: pack

parse = (off=1) =>
  len, _type, name, _off = su ">H B s2", @, off
  setmetatable({:len, :name, type: _type}, _mt), _off

:parse, :pack
