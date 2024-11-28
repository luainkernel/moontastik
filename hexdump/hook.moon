DEBUG = true
XDP = false
NETFILTER = not XDP

xdp = require"xdp"
nf = require"netfilter"
{:register, family: {:IPV6, :IPV4}} = nf
pfs = {IPV6, IPV4}
:ntoh16 = require"linux"
require"ipparse"
IP = require"ipparse.l3.auto_ip"
:collect = require"ipparse.l3.fragmented_ip4"
TCP = require"ipparse.l4.tcp"
UDP = require"ipparse.l4.udp"

protocols =
  [TCP.protocol_type]: "TCP"
  [UDP.protocol_type]: "UDP"

dump = =>
  return nil if not @
  if @is_fragment!
    print"Fragment detected: #{@length}" if DEBUG
    f_ip = collect @
    return true unless f_ip  -- Delay dumping after receiving the last fragment
    print"Last fragment received" if DEBUG
    @ = f_ip
  pkt = UDP(@data)
  print"\n\n#{@src} #{pkt.sport}    #{@dst} #{pkt.dport}    #{protocols[@protocol] or @protocol}\n"
  print l for l in @hexdump!

if XDP
  PASS = xdp.action.PASS
  xdp.attach (skb, arg) ->
    off = ntoh16 arg\getuint16 0
    dump IP :skb, :off
    PASS

if NETFILTER
  CONTINUE = nf.action.CONTINUE
  for i = 1, #pfs
    register {
      pf: pfs[i],
      hooknum: nf.inet_hooks.PRE_ROUTING,
      priority: nf.ip_priority.FILTER,
      hook: (skb) ->
        dump IP :skb
        CONTINUE
    }

