:subclass = require"ipparse"
TLSExtension = require"ipparse.l7.tls.handshake.extension"

subclass TLSExtension, {
  __name: "ServerNameIndication"

  extension_type: 0x00

  type_str: "server name"

  _get_server_name: => @str 9, @short 7
}
