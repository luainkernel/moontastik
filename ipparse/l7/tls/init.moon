pack: sp, unpack: su = string
:bidirectional = require"ipparse.fun"

pack = =>
  sp ">B BB H", @type, @ver, @subver, @len

_mt =
  __tostring: pack

parse = (off=1) =>
  _type, ver, subver, len, _off = su ">B BB H", @, off
  setmetatable({
    type: _type, data_off: _off
    :ver, :subver, :len
  }, _mt), _off

record_types = bidirectional {
  [0x14]: "change_cipher_spec"
  [0x15]: "alert"
  [0x16]: "handshake"
  [0x17]: "application_data"
  [0x18]: "heartbeat"
}

:parse, :pack, :record_types
