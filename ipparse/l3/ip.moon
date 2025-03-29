:bidirectional = require"ipparse.fun"
:IP6, :IP4 = require"ipparse.l2.ethernet".proto
parse: ip6, new: ip6_new, pack: ip6_pack, :ip62s, :s2ip6, :net62s, :s2net6 = require"ipparse.l3.ip6"
parse: ip4, new: ip4_new, pack: ip4_pack, :ip42s, :s2ip4, :net42s, :s2net4 = require"ipparse.l3.ip4"
:sub, unpack: su = string

get_version = (off) =>  -- Accepts data string; returns IP version
  su("B", @, off) >> 4

pack = =>  -- Packs IP data into a binary string
  @version == 6 and ip6_pack(@) or ip4_pack(@)

parse = (off, eth_proto) =>  -- Accepts data string; returns IP packet properties
  res = if eth_proto == IP6
    ip6 @, off
  elseif eth_proto == IP4
    ip4 @, off
  else
    v = get_version @, off
    switch v
      when 6
        ip6 @, off
      when 4
        ip4 @, off
      else return nil, "Unknown IP version #{v}"
  res.total_len or= res.payload_len + 40
  res.payload_len or= res.total_len - res.data_off
  res.next_header or= res.protocol
  res.protocol or= res.next_header
  res

new = =>
  @version == 6 and ip6_new(@) or ip4_new(@)

ip2s = =>  -- Accepts data string; returns IP as readable string
  (#@ == 16 and ip62s or #@ == 4 and ip42s) @

s2ip = =>  -- Accepts readable string; returns IP as data string
  @match":" and s2ip6(@) or s2ip4(@)

net2s = =>  -- Accepts data string; returns subnet as readable string.
  (#@ == 17 and net62s or #@ == 5 and net42s) @

s2net = =>  -- Accepts readable string; retuns subnet as data string
  (@match":" and s2net6 or @match"%." and s2net4) @

contains_ip = (i, nmask) =>  -- Accepts 2 data strings; checks whether net @ contains ip
  if not nmask
    return false if #@ ~= #i+1
    nmask = su "B", @
    return sub(@, 2) == i if nmask == 128
  fmt, shft = "c#{nmask >> 3}B", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, i
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

contains_subnet = (subnet) =>  -- Accepts 2 data strings; checks whether net @ contains subnet
  return false if #@ ~= #subnet
  nmask, smask = su("B", @), su("B", subnet)
  return false if nmask > smask
  return @ == subnet if nmask == smask
  contains_ip @, sub(subnet, 2), nmask

proto = bidirectional {
  ICMP:   0x01
  TCP:    0x06
  UDP:    0x11
  GRE:    0x2F
  ESP:    0x32
  ICMPv6: 0x3A
  OSPF:   0x59
}


:get_version, :parse, :new, :pack, :proto, :ip2s, :s2ip, :net2s, :s2net, :contains_subnet, :contains_ip
