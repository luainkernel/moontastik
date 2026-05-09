# Get Started — full L2 → DNS / HTTPS (SNI) / QUIC (SNI) parsing

This guide shows how to start from a **raw Ethernet frame** and parse up to L7 with `ipparse`.

## 1) Prerequisites

```bash
make && sudo make install
```

## 2) Shared L2 → L4 pipeline

### MoonScript

```moon
eth = require "ipparse.l2.ethernet"
ip  = require "ipparse.l3.ip"
udp = require "ipparse.l4.udp"
tcp = require "ipparse.l4.tcp"

parse_l2_l4 = (frame) ->
  eth_h, l3_off = eth.parse frame, 1
  assert eth_h, "invalid ethernet"

  ip_h, l4_off = ip.parse frame, l3_off, eth_h.protocol
  assert ip_h, "invalid ip"

  if ip_h.protocol == ip.proto.UDP
    udp_h, l7_off = udp.parse frame, l4_off
    return eth_h, ip_h, udp_h, nil, l7_off
  if ip_h.protocol == ip.proto.TCP
    tcp_h, l7_off = tcp.parse frame, l4_off
    return eth_h, ip_h, nil, tcp_h, l7_off

  eth_h, ip_h, nil, nil, nil
```

### Lua

```lua
local eth = require("ipparse.l2.ethernet")
local ip  = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local tcp = require("ipparse.l4.tcp")

local function parse_l2_l4(frame)
  local eth_h, l3_off = eth.parse(frame, 1)
  assert(eth_h, "invalid ethernet")

  local ip_h, l4_off = ip.parse(frame, l3_off, eth_h.protocol)
  assert(ip_h, "invalid ip")

  if ip_h.protocol == ip.proto.UDP then
    local udp_h, l7_off = udp.parse(frame, l4_off)
    return eth_h, ip_h, udp_h, nil, l7_off
  elseif ip_h.protocol == ip.proto.TCP then
    local tcp_h, l7_off = tcp.parse(frame, l4_off)
    return eth_h, ip_h, nil, tcp_h, l7_off
  end

  return eth_h, ip_h, nil, nil, nil
end
```

---

## 3) Full DNS parsing from L2 (Ethernet/IP/UDP/DNS)

### MoonScript

```moon
dns = require "ipparse.l7.dns"
eth = require "ipparse.l2.ethernet"
ip  = require "ipparse.l3.ip"

parse_dns_from_frame = (frame) ->
  eth_h, ip_h, udp_h, _, l7_off = parse_l2_l4 frame
  assert udp_h, "not udp"

  msg, _, err = dns.parse frame, l7_off, false -- false: DNS over UDP
  assert msg, err or "invalid dns"

  {
    src_mac: eth.mac2s eth_h.src
    dst_mac: eth.mac2s eth_h.dst
    src_ip: ip.ip2s ip_h.src
    dst_ip: ip.ip2s ip_h.dst
    src_port: udp_h.spt
    dst_port: udp_h.dpt
    qname: msg.question and msg.question.name or nil
    qtype: msg.question and dns.types[msg.question.qtype] or nil
    rcode: dns.rcodes[msg.header.rcode]
  }
```

### Lua

```lua
local dns = require("ipparse.l7.dns")
local eth = require("ipparse.l2.ethernet")
local ip  = require("ipparse.l3.ip")

local function parse_dns_from_frame(frame)
  local eth_h, ip_h, udp_h, _, l7_off = parse_l2_l4(frame)
  assert(udp_h, "not udp")

  local msg, _, err = dns.parse(frame, l7_off, false)
  assert(msg, err or "invalid dns")

  return {
    src_mac = eth.mac2s(eth_h.src),
    dst_mac = eth.mac2s(eth_h.dst),
    src_ip = ip.ip2s(ip_h.src),
    dst_ip = ip.ip2s(ip_h.dst),
    src_port = udp_h.spt,
    dst_port = udp_h.dpt,
    qname = msg.question and msg.question.name or nil,
    qtype = msg.question and dns.types[msg.question.qtype] or nil,
    rcode = dns.rcodes[msg.header.rcode],
  }
end
```

---

## 4) Full HTTPS parsing from L2 (Ethernet/IP/TCP/TLS/SNI)

SNI is carried in the TLS `server_name` extension of the **ClientHello**.

### MoonScript

```moon
tls = require "ipparse.l7.tls"
hs  = require "ipparse.l7.tls.handshake"
ch  = require "ipparse.l7.tls.handshake.client_hello"
ext = require "ipparse.l7.tls.handshake.extension"
sn  = require "ipparse.l7.tls.handshake.extension.server_name"
ip  = require "ipparse.l3.ip"

parse_https_sni_from_frame = (frame) ->
  _, ip_h, _, tcp_h, l7_off = parse_l2_l4 frame
  assert tcp_h, "not tcp"

  rec, rec_payload_off = tls.parse frame, l7_off
  assert rec and rec.type == 0x16, "not a TLS Handshake record"

  h, body_off = hs.parse frame, rec_payload_off
  assert h and h.type == 0x01, "not ClientHello"

  cli = ch.parse(frame, body_off)
  assert cli, "invalid ClientHello"

  off = 1
  while off <= #cli.extensions
    e, next_off = ext.parse cli.extensions, off
    if e.type == 0x0000
      server_name = sn.parse e.data, 1
      return {
        src_ip: ip.ip2s ip_h.src
        dst_ip: ip.ip2s ip_h.dst
        src_port: tcp_h.spt
        dst_port: tcp_h.dpt
        sni: server_name and server_name.name or nil
      }
    off = next_off

  nil
```

### Lua

```lua
local tls = require("ipparse.l7.tls")
local hs  = require("ipparse.l7.tls.handshake")
local ch  = require("ipparse.l7.tls.handshake.client_hello")
local ext = require("ipparse.l7.tls.handshake.extension")
local sn  = require("ipparse.l7.tls.handshake.extension.server_name")
local ip  = require("ipparse.l3.ip")

local function parse_https_sni_from_frame(frame)
  local _, ip_h, _, tcp_h, l7_off = parse_l2_l4(frame)
  assert(tcp_h, "not tcp")

  local rec, rec_payload_off = tls.parse(frame, l7_off)
  assert(rec and rec.type == 0x16, "not a TLS Handshake record")

  local h, body_off = hs.parse(frame, rec_payload_off)
  assert(h and h.type == 0x01, "not ClientHello")

  local cli = ch.parse(frame, body_off)
  assert(cli, "invalid ClientHello")

  local off = 1
  while off <= #cli.extensions do
    local e, next_off = ext.parse(cli.extensions, off)
    if e.type == 0x0000 then
      local server_name = sn.parse(e.data, 1)
      return {
        src_ip = ip.ip2s(ip_h.src),
        dst_ip = ip.ip2s(ip_h.dst),
        src_port = tcp_h.spt,
        dst_port = tcp_h.dpt,
        sni = server_name and server_name.name or nil
      }
    end
    off = next_off
  end

  return nil
end
```

> Note: in real traffic, a ClientHello can be split across multiple TCP packets.  
> Provide a reassembled TCP stream when needed.

---

## 5) Full QUIC parsing from L2 (Ethernet/IP/UDP/QUIC Initial/SNI)

`ipparse.l7.quic.session` consumes QUIC Initial datagrams (UDP payload), decrypts them, reassembles CRYPTO frames, and exposes SNI.

### MoonScript

```moon
quic = require "ipparse.l4.quic"
qsession = require "ipparse.l7.quic.session"

parse_quic_sni_from_frame = (frame, session) ->
  _, _, udp_h, _, l7_off = parse_l2_l4 frame
  assert udp_h, "not udp"

  qh = quic.parse frame, l7_off
  assert qh and qh.long_header and qh.pkt_type == 0x00, "not QUIC Initial long header"

  udp_payload = frame\sub l7_off
  ok, err = session\push udp_payload
  return nil, err unless ok

  session\sni!

sess = qsession.new!
for frame in *frames
  sni, err = parse_quic_sni_from_frame frame, sess
  if sni
    print "QUIC SNI: #{sni}"
    break
```

### Lua

```lua
local quic = require("ipparse.l4.quic")
local qsession = require("ipparse.l7.quic.session")

local function parse_quic_sni_from_frame(frame, session)
  local _, _, udp_h, _, l7_off = parse_l2_l4(frame)
  assert(udp_h, "not udp")

  local qh = quic.parse(frame, l7_off)
  assert(qh and qh.long_header and qh.pkt_type == 0x00, "not QUIC Initial long header")

  local udp_payload = frame:sub(l7_off)
  local ok, err = session:push(udp_payload)
  if not ok then
    return nil, err
  end
  return session:sni()
end

local sess = qsession.new()
for _, frame in ipairs(frames) do
  local sni, err = parse_quic_sni_from_frame(frame, sess)
  if sni then
    print("QUIC SNI:", sni)
    break
  end
end
```

The crypto backend is auto-detected in this order:

1. `ipparse.lib.crypto.backend.lunatik`
2. `ipparse.lib.crypto.backend.ffi_wolfssl`
3. `ipparse.lib.crypto.backend.ffi_mbedtls`
4. `ipparse.lib.crypto.backend.ffi_openssl`

---

## 6) Real repository example

```bash
luajit /PATH/TO/ipparse/examples/parse_real_quic.lua /path/to/capture.pcapng
```

This example performs the full L2 → QUIC → SNI flow on a real capture.
