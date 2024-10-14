IP = require"ipparse.l3.ip"
IPn =
  [4]: require"ipparse.l3.ip4"
  [6]: require"ipparse.l3.ip6"


=>
  if ip = IPn[IP(@).version]
    ip @

