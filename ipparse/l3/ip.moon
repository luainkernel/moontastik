:bidirectional = require"ipparse.fun"
:IP6, :IP4 = require"ipparse.l2.ethernet".proto
:ip6, :ip62s, :s2ip6, :net62s, :s2net6 = require"ipparse.l3.ip6"
:ip4, :ip42s, :s2ip4, :net42s, :s2net4 = require"ipparse.l3.ip4"
su = string.unpack

get_version = (off) =>  -- Accepts data string; returns IP version
  su("B", @, off) >> 4

ip = (off, eth_proto) =>  -- Accepts data string; returns IP packet properties
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

ip2s = =>  -- Accepts data string; returns IP as readable string
  (#@ == 16 and ip62s or #@ == 4 and ip42s) @

s2ip = =>  -- Accepts readable string; returns IP as data string
  @match":" and s2ip6(@) or s2ip4(@)

net2s = =>  -- Accepts data string; returns subnet as readable string.
  (#@ == 17 and net62s or #@ == 5 and net42s) @

s2net = =>  -- Accepts readable string; retuns subnet as data string
  (@match":" and s2net6 or @match"%." and s2net4) @

contains_subnet = (subnet) =>  -- Accepts 2 data strings; checks whether net @ contains subnet
  return false if #@ ~= #subnet
  nmask = su "B", @
  smask = su "B", subnet
  return false if nmask > smask
  fmt, shft = "c#{nmask >> 3}", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, subnet, 2
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

contains_ip = (i) =>  -- Accepts 2 data strings; checks whether net @ contains ip
  return false if #@ ~= #i+1
  nmask = su "B", @
  fmt, shft = "c#{nmask >> 3}", 8 - (nmask & 0x7)
  nbytes, nbits = su fmt, @, 2
  sbytes, sbits = su fmt, i
  return true if nbytes == sbytes and (nbits >> shft) == (sbits >> shft)
  false

proto =
  ICMP:   0x01
  TCP:    0x06
  UDP:    0x11
  GRE:    0x2F
  ESP:    0x32
  ICMPv6: 0x3A
  OSPF:   0x59
proto = bidirectional proto


:get_version, :ip, :ip6, :ip4, :proto, :ip2s, :s2ip, :net2s, :s2net, :contains_subnet, :contains_ip

