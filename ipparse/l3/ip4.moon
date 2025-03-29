:format, :sub, pack: sp, unpack: su = string
:checksum, :pseudo_header = require "ipparse.l3.lib"

pack = =>
  if data = @data
    d = "#{data}"  -- Let the L4 payload recalculate its length
    data.checksum = 0
    d = "#{data}"
    data.checksum = checksum(pseudo_header(d, @src, @dst, @protocol) .. d)
    header_len = 20 + #@options
    @ihl = header_len >> 2
    @total_len = header_len + #d
  @checksum = checksum sp(">BBHHHBBH c4c4", @v_ihl, @tos, @total_len, @id, @ff, @ttl, @protocol, 0, @src, @dst)..@options
  sp(">BBHHHBBH c4c4", @v_ihl, @tos, @total_len, @id, @ff, @ttl, @protocol, @checksum, @src, @dst) .. @options .. "#{@data or ''}"

_mt = __tostring: pack

parse = (off=1) =>  -- Accepts data string; returns IPv4 header informations
  v_ihl, tos, total_len, id, ff, ttl, protocol, cksum, src, dst, _off = su ">BBHHHBBH c4c4", @, off
  version, ihl = v_ihl >> 4, v_ihl & 0x0f
  payload_off = ihl << 2
  data_off = off + payload_off
  options = sub @, _off, data_off-1
  setmetatable({
    :version, :ihl, :v_ihl, :off, :payload_off, :data_off
    :tos, :total_len, :id, :ff, :ttl
    :protocol, checksum: cksum, :src, :dst
    :options
  }, _mt), _off

new = =>  -- TODO: handle options
  @v_ihl or= ((@version << 4) | @ihl)
  setmetatable @, _mt

ip42s = =>  -- Accepts data string; returns IPv4 address as readable string
 format "%d.%d.%d.%d", su "BBBB", @

s2ip4 = =>  -- Accepts readable string; returns IPv4 address as data string
  sp "BBBB", @match"(%d+)%.(%d+)%.(%d+)%.(%d+)"

net42s = =>  -- Accepts data string; returns IPv4 address as readable string
  m, a, b, c, d = su "BBBBB", @
  format "%d.%d.%d.%d/%d", a, b, c, d, m

s2net4 = =>
  b1, b2, b3, b4, mask = @match"(%d+)%.(%d+)%.(%d+)%.(%d+)/?(%d*)"
  sp "B BBBB", (tonumber(mask) or 32), tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4)


:parse, :new, :pack, :ip42s, :s2ip4, :net42s, :s2net4
