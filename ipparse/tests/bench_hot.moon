--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Micro-banc des chemins chauds de parsing/packing (hot path DNS de custos).
-- Mesure le coût par appel (µs, minimum de N passages) ET l'allocation par
-- appel (octets, GC arrêté) des fonctions qui dominent le profil de
-- `docs/agents/perf.md` §18 (custos) :
--
--   * `l7.dns` : `parse` (requête / réponse 8 A / réponse CNAME compressée),
--     `labels` (noms de RRs) ;
--   * `lib.pack_compat` : `sp`/`su` sur les formats réellement utilisés par
--     le hot path (`>BBHHHBBH c4c4` IP4, `>c4c4 x B s2` pseudo-header,
--     `>H H H H` UDP, `>H B B H H H H` en-tête DNS, `>H H I4 H` RR) ;
--   * `l3.lib.checksum` : sur un en-tête IP (20 o) et sur un paquet UDP ;
--   * le chemin complet de duplication validateur de custos (`ip4.pack` avec
--     payload UDP → recalcule les deux checksums) ;
--   * `l3.ip4.parse` + `l4.udp.parse` (décapsulation).
--
-- Aucune sortie disque hors de `BENCH_OUT`/`BENCH_BASELINE` (fichiers passés
-- par l'environnement). Ne fait partie d'aucune suite : `run_all` ne l'appelle
-- pas.
--
-- Usage (depuis le parent du dossier `ipparse`) :
--   LUA_PATH="./?.lua;./?/init.lua" luajit ipparse/tests/bench_hot.lua
--   BENCH_OUT=tmp/bench_after.txt        -- écrit les mesures
--   BENCH_BASELINE=tmp/bench_before.txt  -- colonne de delta
--   BENCH_ONLY=sp_                       -- filtre par sous-chaîne
--   BENCH_ITERS / BENCH_REPEATS / BENCH_WARMUP / BENCH_ALLOC_ITERS

{:hex2bin} = require "ipparse.init"
dns = require "ipparse.l7.dns"
ip4 = require "ipparse.l3.ip4"
udp = require "ipparse.l4.udp"
{ :checksum } = require "ipparse.l3.lib"
{ pack: sp, unpack: su } = require "ipparse.lib.pack_compat"
{ new: new_ip } = require "ipparse.l3.ip"
{ new: new_udp } = require "ipparse.l4.udp"

os_clock = os.clock
env_num = (name, d) ->
  v = os.getenv name
  (v and tonumber v) or d

ITERS       = env_num "BENCH_ITERS", 300000
REPEATS     = env_num "BENCH_REPEATS", 5
WARMUP      = env_num "BENCH_WARMUP", 5000
ALLOC_ITERS = env_num "BENCH_ALLOC_ITERS", 2000
ONLY        = os.getenv "BENCH_ONLY"
OUT_PATH    = os.getenv "BENCH_OUT"
BASE_PATH   = os.getenv "BENCH_BASELINE"

-- ── Données de test ────────────────────────────────────────────────────────

SRC4 = "\10\35\1\2"      -- 10.35.1.2
DST4 = "\10\35\1\1"      -- 10.35.1.1
SRC6 = "\252\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1"

-- QNAME : controlplane.login.tailscale.com (4 labels, 35 o encodés)
QNAME_HEX = "0b636f6e74726f6c70616e65" .. "056c6f67696e" ..
  "097461696c7363616c65" .. "03636f6d" .. "00"

-- Requête A (QR=0, QDCOUNT=1)
QUERY_HEX = "123401000001000000000000" .. QNAME_HEX .. "00010001"

-- Réponse A avec 8 RRs (profil « second avis » de perf.md §16.3) : chaque
-- answer pointe sur le QNAME (0xc00c).
RESP8_HEX = "123481800001000800000000" .. QNAME_HEX .. "00010001"
for i = 1, 8
  RESP8_HEX = RESP8_HEX .. "c00c00010001" .. "0000012c" .. "0004" .. "6440000#{i}"

-- Réponse CNAME : QNAME www.example.com, answer 1 = CNAME vers example.com
-- (nom complet en clair dans le RDATA), answer 2 = A pointant sur ce RDATA.
CNAME_HEX = "123481800001000200000000" ..
  "03777777076578616d706c6503636f6d00" .. "00010001" ..
  "c00c" .. "00050001" .. "0000012c" .. "0012" ..
  "076578616d706c6503636f6d00" ..
  "c01e" .. "00010001" .. "0000012c" .. "0004" .. "5db8d822"

query  = hex2bin QUERY_HEX
resp8  = hex2bin RESP8_HEX
resp_c = hex2bin CNAME_HEX

-- Paquet IP+UDP+DNS complet (décapsulation) et ses morceaux.
udp_pkt = hex2bin (QNAME_HEX .. "00010001")   -- payload DNS de la réponse
hdr20   = sp ">BBHHHBBH c4c4", 0x45, 0, 40, 1, 0x4000, 64, 17, 0, SRC4, DST4
pkt     = "#{new_ip {
  version: 4, v_ihl: 0x45, tos: 0, id: 1, ff: 0x4000, ttl: 64,
  protocol: 17, src: SRC4, dst: DST4, options: "",
  data: new_udp { spt: 5353, dpt: 53, checksum: 0, data: udp_pkt }
}}"

-- Entrée de `su ">H H I4 H"` (le RR de tête de RESP8 : 12 + 35 + 4 = 47).
RR_OFF = 12 + #QNAME_HEX / 2 + 4 + 1

CSUM_IN = sp(">c4c4 x B s2", SRC4, DST4, 17, udp_pkt) .. udp_pkt

ip_pkt_obj = new_ip {
  version: 4, v_ihl: 0x45, tos: 0, id: 1, ff: 0x4000, ttl: 64,
  protocol: 17, src: SRC4, dst: DST4, options: "",
  data: new_udp { spt: 5353, dpt: 53, checksum: 0, data: udp_pkt }
}

-- ── Cas mesurés ────────────────────────────────────────────────────────────

cases = {
  { "dns_parse_query",  -> dns.parse query, 1, false }
  { "dns_parse_resp8",  -> dns.parse resp8, 1, false }
  { "dns_parse_resp_cname", -> dns.parse resp_c, 1, false }
  { "dns_parse_header", -> dns.parse_header resp8, 1, false }
  { "dns_parse_question", -> dns.parse_question resp8, 13, 1 }
  { "dns_parse_rr",     -> dns.parse_rr resp8, RR_OFF, 1 }
  { "dns_labels",       -> dns.labels resp8, 13, 1 }
  { "ip4_parse",        -> ip4.parse pkt, 1 }
  { "udp_parse",        -> udp.parse pkt, 21 }
  { "sp_ip4hdr",        -> sp ">BBHHHBBH c4c4", 0x45, 0, 40, 1, 0x4000, 64, 17, 0, SRC4, DST4 }
  { "sp_pseudo",        -> sp ">c4c4 x B s2", SRC4, DST4, 17, udp_pkt }
  { "sp_udp",           -> sp ">H H H H", 5353, 53, 40, 0 }
  { "sp_dns_header",    -> sp ">H B B H H H H", 0x1234, 0x8180, 0, 1, 8, 0, 0 }
  { "su_ip4hdr",        -> su ">BBHHHBBH c4c4", pkt, 1 }
  { "su_dns_header",    -> su ">H B B H H H H", resp8, 1 }
  { "su_rr",            -> su ">H H I4 H", resp8, RR_OFF }
  { "checksum_20",      -> checksum hdr20 }
  { "checksum_udp",     -> checksum CSUM_IN }
  { "ip4_pack_udp",     -> "#{ip_pkt_obj}" }
}

-- ── Mesure ─────────────────────────────────────────────────────────────────

measure = (fn) ->
  for i = 1, WARMUP
    fn!
  best = math.huge
  for r = 1, REPEATS
    t0 = os_clock!
    for i = 1, ITERS
      fn!
    dt = os_clock! - t0
    best = dt if dt < best
  -- Allocation : GC arrêté, delta de la mémoire occupée.
  collectgarbage "collect"
  collectgarbage "stop"
  b0 = collectgarbage "count"
  for i = 1, ALLOC_ITERS
    fn!
  b1 = collectgarbage "count"
  collectgarbage "restart"
  collectgarbage "collect"
  best / ITERS * 1e6, (b1 - b0) * 1024 / ALLOC_ITERS

load_baseline = (path) ->
  base = {}
  f = io.open path, "r"
  return base unless f
  for line in f\lines!
    name, us, bytes = line\match "^(%S+)%s+(%S+)%s+(%S+)$"
    base[name] = { us: tonumber(us), bytes: tonumber(bytes) } if name
  f\close!
  base

pct = (now, before) ->
  return "" unless before and before > 0
  d = (now - before) / before * 100
  ("%+.1f%%")\format d

results = {}
for c in *cases
  name, fn = c[1], c[2]
  continue if ONLY and not name\find ONLY, 1, true
  us, bytes = measure fn
  results[#results+1] = { name: name, us: us, bytes: bytes }

base = if BASE_PATH then load_baseline(BASE_PATH) else {}

if OUT_PATH
  f = io.open OUT_PATH, "w"
  if f
    for r in *results
      f\write ("#{r.name}\t#{r.us}\t#{r.bytes}\n")
    f\close!

jit_info = if type(jit) == "table"
  "#{jit.version} / #{jit.arch}"
else
  "non-LuaJIT (_VERSION=#{_VERSION})"

print "# Micro-banc ipparse — chemins chauds"
print ""
print "- #{jit_info}"
print "- iters=#{ITERS}, repeat=#{REPEATS} (minimum retenu), warmup=#{WARMUP}, alloc_iters=#{ALLOC_ITERS}"
if BASE_PATH
  print "- baseline : #{BASE_PATH}"
print ""
print "| cas | µs/appel | Δ baseline | o/appel | Δ baseline |"
print "|---|---|---|---|---|"

for r in *results
  b = base[r.name]
  row = ("| #{r.name} | %.4f | %s | %.0f | %s |")\format(
    r.us, pct(r.us, b and b.us), r.bytes, pct(r.bytes, b and b.bytes))
  print row

print "\n(mesures écrites : #{OUT_PATH})" if OUT_PATH
