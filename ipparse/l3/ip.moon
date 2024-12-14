:bidirectional = require"ipparse.fun"
su = string.unpack

proto =
  TCP:    0x06
  UDP:    0x11
  GRE:    0x2F
  ESP:    0x32
  ICMPv6: 0x3A
  OSPF:   0x59
proto = bidirectional proto

get_version = (off) => su("B", @, off) >> 4

ip6 = (off) =>
  -- vtf, payload_len, next_header, hop_limit, src, dst, off
  su "c4 >H B B c16 c16", @, off

ip4 = (off) =>
  v_ihl, tos, len, id, ff, ttl, protocol, header_checksum, src, dst = su "B B >H >H <H B B >H c4 c4", @, off
  ihl = v_ihl & 0x0f
  ihl, tos, len, id, ff, ttl, protocol, header_checksum, src, dst, off+4*ihl

:get_version, :ip6, :ip4, :proto

