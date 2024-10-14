:subclass, :Packet = require"ipparse"
TLSExtension = require"ipparse.l7.tls.handshake.extension"
:min = math
:wrap, :yield = coroutine


TLS_extensions = setmetatable {
  [0x00]: require"ipparse.l7.tls.handshake.extension.server_name"
}, __index: (k) => subclass TLSExtension, {
  __name: "UnknownTlsExtension"

  type_str: => "unknown"
}


subclass Packet, {
  __name: "TLSClientHello"

  message_type: 0x01

  _get_client_version: => "#{@byte 0}.#{@byte 1}"

  _get_client_random: => @str 2, 32

  _get_session_id_length: => @byte 34

  _get_session_id: => @str 35, @session_id_length

  _get_ciphers_offset: => 35 + @session_id_length

  _get_ciphers_length: => @short @ciphers_offset

  _get_ciphers: => [ @short(@ciphers_offset + 2 + i) for i = 0, @ciphers_length-2, 2 ]

  _get_compressions_offset: => @ciphers_offset + 2 + @ciphers_length

  _get_compressions_length: => @byte @compressions_offset

  _get_compressions: => [ @byte(@compressions_offset + 1 + i) for i = 0, @compressions_length - 1 ]

  _get_extensions_offset: => @compressions_offset + 1 + @compressions_length

  _get_extensions: => [ extension for extension in @iter_extensions! ]

  iter_extensions: => wrap ->
    offset = @extensions_offset + 2
    max_offset = min #@skb-@off-6, offset + @short @extensions_offset
    while offset < max_offset
      extension = TLS_extensions[@short offset] skb: @skb, off: @off + offset
      yield extension
      offset += extension.length
}
