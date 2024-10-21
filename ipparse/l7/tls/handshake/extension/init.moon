subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet

subclass Packet, {
  __name: "TLSExtension"

  _get_type: => @short 0

  _get_length: => 4 + @short 2

  types: {
    server_name: 0x00
  }
}
