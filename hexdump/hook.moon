--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

DEBUG = true
XDP = false
NETFILTER = not XDP

xdp = require"xdp"
{:register} = require"netfilter"
action: {:CONTINUE, :PASS}, :inet, ip: {:pri}, proto: {:INET} = require"linux.nf"
pfs = {INET}
:ntoh16 = require"linux"
:hexdump = require"ipparse"
IP = require"ipparse.l3.ip"
:collect = require"ipparse.l3.fragmented_ip4"
TCP = require"ipparse.l4.tcp"
UDP = require"ipparse.l4.udp"

dump = (ip_mod, skb, off) =>
  pkt = ip_mod.parse(skb, off or 1)
  return nil if not pkt

  -- Fragmentation handling (IPv4 specifically)
  if pkt.version == 4 and (pkt.MF or pkt.ff > 0)
    print"Fragment detected: #{pkt.total_len}" if DEBUG
    f_ip = collect pkt
    return true unless f_ip  -- Delay dumping after receiving the last fragment
    print"Last fragment received" if DEBUG
    pkt = f_ip

  -- L4 Parsing
  l4_pkt = nil
  if pkt.protocol == IP.proto.TCP
    l4_pkt = TCP.parse(pkt.data)
  elseif pkt.protocol == IP.proto.UDP
    l4_pkt = UDP.parse(pkt.data)

  if l4_pkt
    print"hex: --- #{IP.ip2s pkt.src} #{l4_pkt.spt}    #{IP.ip2s pkt.dst} #{l4_pkt.dpt}    #{IP.proto[pkt.protocol] or pkt.protocol}"
  else
    print"hex: --- #{IP.ip2s pkt.src}        #{IP.ip2s pkt.dst}    #{IP.proto[pkt.protocol] or pkt.protocol}"

  print "hex: "..l for l in pkt.hexdump!

if XDP
  PASS = action.PASS
  xdp.attach (skb, arg) ->
    off = ntoh16 arg\getuint16 0
    dump IP, skb, off
    PASS

if NETFILTER
  CONTINUE = action.CONTINUE
  for i = 1, #pfs
    register {
      pf: pfs[i],
      hooknum: inet.LOCAL_OUT,
      priority: pri.FILTER,
      hook: (skb) ->
        dump IP, skb
        CONTINUE
    }
