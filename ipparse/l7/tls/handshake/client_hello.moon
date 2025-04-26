pack: sp, unpack: su = string

pack = =>
  sp ">H c32 s1 s2 s1 s2", @version, @client_random, @session_id, @ciphers, @compressions, @extensions

_mt =
  __tostring: pack

parse = (off=1) =>
  version, client_random, session_id, ciphers, compressions, extensions, _off = su ">H c32 s1 s2 s1 s2", @, off
  setmetatable({
    :version, :client_random, :session_id, :ciphers, :compressions, :extensions
  }, _mt), _off

:parse, :pack
