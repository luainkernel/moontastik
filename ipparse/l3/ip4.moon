:format, pack: sp, unpack: su = string

has_options = => @data_off > 20

ip4 = (off=0) =>  -- Accepts data string; returns IPv4 header informations
  v_ihl, tos, total_len, id, ff, ttl, protocol, checksum, src, dst, _off = su ">BBHHHBBH c4c4", @, off
  version, ihl = v_ihl >> 4, v_ihl & 0x0f
  payload_off = ihl << 2
  {
    :version, :ihl, :off, :payload_off, data_off: off + payload_off
    :tos, :total_len, :id, :ff, :ttl
    :protocol, :checksum, :src, :dst
    :has_options
  }, _off

ip42s = =>  -- Accepts data string; returns IPv4 address as readable string
 format "%d.%d.%d.%d", su "BBBB", @

s2ip4 = =>  -- Accepts readable string; returns IPv4 address as data string
  sp "BBBB", @match"(%d+)%.(%d+)%.(%d+)%.(%d+)"

net42s = =>  -- Accepts data string; returns IPv4 address as readable string
  m, a, b, c, d = su "BBBBB", @
  format "%d.%d.%d.%d/%d", a, b, c, d, m

s2net4 = =>
  b1, b2, b3, b4, mask = @match"(%d+)%.(%d+)%.(%d+)%.(%d+)/?(%d+)"
  sp "B BBBB", (tonumber mask or 32), tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4)


:ip4, :ip42s, :s2ip4, :net42s, :s2net4
