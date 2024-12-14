subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet
range, wrap = do
  _ = require"ipparse.fun"
  _.range, _.wrap
TLSExtension = require"ipparse.l7.tls.handshake.extension"
min = math.min
co_wrap, co_yield = coroutine.wrap, coroutine.yield


TLS_extensions =
  [0x00]: require"ipparse.l7.tls.handshake.extension.server_name"

setmetatable TLS_extensions, __index: (extension_type) =>
  subclass TLSExtension, __name: "UnknownTlsExtension", :extension_type, type_str: "unknown"


subclass Packet, {
  __name: "TLSClientHello"

  message_type: 0x01

  _get_client_version: => "#{@byte 0}.#{@byte 1}"

  _get_client_random: => @str 2, 32

  _get_session_id_length: => @byte 34

  _get_session_id: => @str 35, @session_id_length

  _get_ciphers_offset: => 35 + @session_id_length

  _get_ciphers_length: => @short @ciphers_offset

  _get_ciphers: => range(0, @ciphers_lenght-2, 2)\map((i) -> @short(@ciphers_offset + 2 + i))\toarray!

  _get_compressions_offset: => @ciphers_offset + 2 + @ciphers_length

  _get_compressions_length: => @byte @compressions_offset

  _get_compressions: => range(0, @compressions_length-1)\map((i) -> @byte(@compressions_offset + 1 + i))\toarray!

  _get_extensions_offset: => @compressions_offset + 1 + @compressions_length

  _get_extensions: => wrap(@iter_extensions)\toarray!

  iter_extensions: => co_wrap ->
    offset = @extensions_offset + 2
    max_offset = min #@_data-@off-6, offset + @short @extensions_offset
    while offset < max_offset
      extension = TLS_extensions[@short offset] _data: @_data, off: @off + offset
      co_yield extension
      offset += extension.length
}
