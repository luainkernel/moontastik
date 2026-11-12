--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Équivalence du parsing des noms DNS avec le code d'origine.
-- `l7.dns` lit désormais les noms en une seule passe (`label_parts` /
-- `walk_name`, un seul tableau de segments et un seul `table.concat` par nom,
-- `visited` allouée seulement si un second saut de compression est nécessaire),
-- au lieu de `labels` + `concat`. Ce fichier contient des **copies littérales
-- du code d'avant** cette réécriture (`ref_label`, `ref_labels`,
-- `ref_parse_question`, `ref_parse_rr`, `ref_parse`) et vérifie, sur un corpus
-- de paquets (valides, malformés, chaînes de pointeurs, noms de 1100
-- segments, tampons pseudo-aléatoires déterministes) et à **chaque offset** :
--
--   * `label` : les 4 valeurs de retour (segment, offset suivant, drapeau
--     pointeur, message ET offset d'erreur) ;
--   * `labels` : le tableau segment par segment, l'offset et l'erreur ;
--   * `parse_question` / `parse_rr` / `parse` : chaque champ, l'offset
--     suivant et le message d'erreur.
--
-- Toute divergence entre l'implémentation courante et ces copies fait échouer
-- les tests ci-dessous.

util = require"ipparse.lib.util"
{:test} = util
dns = require"ipparse.l7.dns"
{:need_bytes} = require "ipparse"
{:byte, :sub} = string
{:concat} = table
{:band, :lshift} = require"ipparse.lib.bit_compat"
{pack: sp, unpack: su} = require "ipparse.lib.pack_compat"
{:hex2bin} = require "ipparse.init"

-- ── Références : code d'origine, littéralement ─────────────────────────────

local ref_labels

ref_label = (s, off, l7_off=1, visited=nil, depth=0) ->
  return nil, off, nil, "invalid label offset #{off}" unless need_bytes s, off, 1
  size = byte s, off
  _off = off + 1
  if size == 0  -- End of label
    return nil, off+1
  if band(size, 0xC0) == 0xC0  -- DNS label compression pointer
    return nil, off, nil, "truncated DNS compression pointer" unless need_bytes s, off, 2
    pos = byte s, off + 1
    ptr = lshift(band(size, 0x3F), 8) + pos
    target_off = l7_off + ptr
    return nil, _off + 1, nil, "DNS compression pointer out of bounds (#{ptr})" unless target_off >= l7_off and target_off <= #s
    return nil, _off + 1, nil, "DNS compression pointer recursion limit reached" if depth >= 32
    return nil, _off + 1, nil, "DNS compression pointer loop at #{ptr}" if visited and visited[target_off]
    visited or= {}
    visited[target_off] = true
    pointed_labels, _, err = ref_labels s, target_off, l7_off, visited, depth + 1
    return nil, _off + 1, nil, err unless pointed_labels
    return concat(pointed_labels, "."), _off + 1, true
  if band(size, 0xC0) == 0  -- Normal case
    return nil, off, nil, "truncated DNS label (len=#{size})" unless need_bytes s, off + 1, size
    return sub(s, off + 1, off + size), off + size + 1
  nil, off, nil, "invalid DNS label prefix at offset #{off}"

ref_labels = (s, off, l7_off, visited=nil, depth=0) ->
  lbls = {}
  for i = 1, 1024
    lbl_segment, next_parse_off, is_from_pointer, err = ref_label s, off, l7_off, visited, depth
    return nil, off, err if err
    if not lbl_segment
      off = next_parse_off
      break
    lbls[i] = lbl_segment
    off = next_parse_off
    if is_from_pointer
      break
  lbls, off

ref_parse_question = (s, off, l7_off) ->
  lbls, _off, err = ref_labels s, off, l7_off
  return nil, off, err unless lbls
  return nil, off, "truncated DNS question fields" unless need_bytes s, _off, 4
  qname = sub s, off, _off-1
  qtype, qclass, _off = su ">H H", s, _off
  { name: concat(lbls, "."), :qname, :qtype, :qclass, :off, end_off: _off-1 }, _off

ref_parse_rr = (s, off, l7_off) ->
  lbls, _off, err = ref_labels s, off, l7_off
  return nil, off, err unless lbls
  return nil, off, "truncated DNS resource record header" unless need_bytes s, _off, 10
  rname = sub s, off, _off-1
  rtype, rclass, ttl, rdlen, _off = su ">H H I4 H", s, _off
  return nil, off, "truncated DNS resource record data" unless need_bytes s, _off, rdlen
  rdata = sub s, _off, _off + rdlen - 1
  _off += rdlen
  { name: concat(lbls, "."), :rname, :rtype, :rclass, :ttl, :rdata, :off, end_off: _off-1 }, _off

ref_parse_section = (s, off, count, l7_off) ->
  res = {}
  for i = 1, count
    r, off, err = ref_parse_rr s, off, l7_off
    return nil, off, err unless r
    res[i] = r
  res, off

ref_parse_questions = (s, off, qdcount, l7_off) ->
  res = {}
  for i = 1, qdcount
    q, off, err = ref_parse_question s, off, l7_off
    return nil, off, err unless q
    res[i] = q
  res, off

ref_parse = (s, l7_off, is_tcp) ->
  header, _off_or_err = dns.parse_header s, l7_off, is_tcp
  return nil, l7_off, _off_or_err or "No DNS data" unless header
  _off = _off_or_err
  questions, _off, err = ref_parse_questions s, _off, header.qdcount, l7_off
  return nil, _off, err unless questions
  answers, _off, err = ref_parse_section s, _off, header.ancount, l7_off
  return nil, _off, err unless answers
  authorities, _off, err = ref_parse_section s, _off, header.nscount, l7_off
  return nil, _off, err unless authorities
  additionals, _off, err = ref_parse_section s, _off, header.arcount, l7_off
  return nil, _off, err unless additionals
  { :header, question: questions[1], :questions, :answers, :authorities, :additionals }, _off

-- ── Corpus ─────────────────────────────────────────────────────────────────

fmt = (v) -> if type(v) == "string" then "\"#{v}\"" else tostring v

-- Requête / réponse de référence (example.com).
query_hex = "123401000001000000000000076578616d706c6503636f6d0000010001"
resp_hex = "123481800001000100000000" ..
  "076578616d706c6503636f6d00" .. "00010001" ..
  "c00c" .. "00010001" .. "00000e10" .. "0004" .. "5db8d822"
-- Chaîne de compression : www.example.com, CNAME → example.com (nom en clair
-- dans le RDATA), A pointant sur ce RDATA, puis A sur le QNAME.
chain_hex = "123481800001000300000000" ..
  "03777777076578616d706c6503636f6d00" .. "00010001" ..
  "c00c" .. "00050001" .. "0000012c" .. "0012" .. "076578616d706c6503636f6d00" ..
  "c01e" .. "00010001" .. "0000012c" .. "0004" .. "5db8d822" ..
  "c00c" .. "00010001" .. "0000012c" .. "0004" .. "01020304"

-- Boucle : le pointeur à l'offset 13 vise l'offset 13 (lui-même).
loop_hex = "000101000001000000000000" .. "c00c" .. "00010001"
-- Boucle à deux maillons : 13 → 15 → 13.
loop2_hex = "000101000001000000000000" .. "c00e" .. "c00c" .. "00010001"
-- Pointeur hors limites (ptr = 0x3FFF) et préfixe d'étiquette invalide (0x80).
oob_hex = "000101000001000000000000" .. "c0ff" .. "00010001"
bad_prefix_hex = "000101000001000000000000" .. "8003616263" .. "00010001"
-- Étiquette tronquée (longueur annoncée > octets fournis).
trunc_hex = "000101000001000000000000" .. "056162"
-- Chaîne de 40 pointeurs (dépasse la limite de 32 sauts) : le i-ème pointeur
-- est à l'offset 13 + 2*(i-1) et vise l'offset suivant (ptr = 12 + 2*i).
chain_parts = {}
for i = 1, 40
  ptr = 12 + 2 * i
  chain_parts[#chain_parts + 1] = sp ">B B", 0xC0 + math.floor(ptr / 256), ptr % 256
chain_parts[#chain_parts + 1] = "\000"
chain40_hex = "000101000001000000000000" .. (table.concat chain_parts)

-- Nom de 1100 segments de 1 octet (dépasse la limite de 1024 segments).
long_parts = {}
for i = 1, 1100
  long_parts[#long_parts + 1] = "01" .. "61"   -- label "a"
long_parts[#long_parts + 1] = "00"
long_name_hex = "000101000001000000000000" .. (table.concat long_parts) .. "00010001"

-- Tampons pseudo-aléatoires déterministes (256 valeurs d'octet, rotations).
_pattern = {}
for i = 0, 255
  _pattern[#_pattern + 1] = string.char i
PATTERN = table.concat _pattern

packets = {
  hex2bin query_hex
  hex2bin resp_hex
  hex2bin chain_hex
  hex2bin loop_hex
  hex2bin loop2_hex
  hex2bin oob_hex
  hex2bin bad_prefix_hex
  hex2bin trunc_hex
  hex2bin chain40_hex
  hex2bin long_name_hex
  (PATTERN .. PATTERN)\sub 3, 130
  (PATTERN .. PATTERN)\sub 100, 240
  (PATTERN .. PATTERN)\sub 200, 256
}

-- ── Comparateurs ───────────────────────────────────────────────────────────

same = (a, b, msg) ->
  assert a == b, "#{msg}: #{fmt a} != #{fmt b}"

same_label = (s, off, pi) ->
  a1, a2, a3, a4 = dns.label s, off, 1
  b1, b2, b3, b4 = ref_label s, off, 1
  where = "label p#{pi} off=#{off}"
  same a1, b1, "#{where} segment"
  same a2, b2, "#{where} offset suivant"
  same a3, b3, "#{where} pointeur"
  same a4, b4, "#{where} erreur"

same_labels = (s, off, pi) ->
  t1, o1, e1 = dns.labels s, off, 1
  t2, o2, e2 = ref_labels s, off, 1
  where = "labels p#{pi} off=#{off}"
  if type(t1) == "table"
    assert type(t2) == "table", "#{where}: la référence renvoie #{fmt t2}"
    same #t1, #t2, "#{where} nombre de segments"
    for i = 1, #t1
      same t1[i], t2[i], "#{where} segment #{i}"
  else
    same t1, t2, "#{where} résultat"
  same o1, o2, "#{where} offset suivant"
  same e1, e2, "#{where} erreur"

same_q = (a, b, msg) ->
  if a == nil or b == nil
    same a, b, msg
    return
  for k in *{"name", "qname", "qtype", "qclass", "off", "end_off"}
    same a[k], b[k], "#{msg}.#{k}"

same_rr = (a, b, msg) ->
  if a == nil or b == nil
    same a, b, msg
    return
  for k in *{"name", "rname", "rtype", "rclass", "ttl", "rdata", "off", "end_off"}
    same a[k], b[k], "#{msg}.#{k}"

same_msg = (a, b, msg) ->
  if a == nil or b == nil
    same a, b, msg
    return
  for k in *{"id", "qdcount", "ancount", "nscount", "arcount", "off", "data_off"}
    same a.header[k], b.header[k], "#{msg}.header.#{k}"
  same #a.questions, #b.questions, "#{msg} #questions"
  for i = 1, #a.questions
    same_q a.questions[i], b.questions[i], "#{msg}.q#{i}"
  for sec in *{"answers", "authorities", "additionals"}
    same #a[sec], #b[sec], "#{msg} ##{sec}"
    for i = 1, #a[sec]
      same_rr a[sec][i], b[sec][i], "#{msg}.#{sec}#{i}"

-- ── Tests ──────────────────────────────────────────────────────────────────

test "label: identique au code d'origine à chaque offset du corpus", ->
  for pi, s in ipairs packets
    for off = 1, #s + 1
      same_label s, off, pi

test "labels: identique au code d'origine à chaque offset du corpus", ->
  for pi, s in ipairs packets
    for off = 1, #s + 1
      same_labels s, off, pi

test "parse_question: identique au code d'origine à chaque offset", ->
  for pi, s in ipairs packets
    for off = 1, #s + 1
      a, ao, ae = dns.parse_question s, off, 1
      b, bo, be = ref_parse_question s, off, 1
      where = "parse_question p#{pi} off=#{off}"
      same_q a, b, where
      same ao, bo, "#{where} offset suivant"
      same ae, be, "#{where} erreur"

test "parse_rr: identique au code d'origine à chaque offset", ->
  for pi, s in ipairs packets
    for off = 1, #s + 1
      a, ao, ae = dns.parse_rr s, off, 1
      b, bo, be = ref_parse_rr s, off, 1
      where = "parse_rr p#{pi} off=#{off}"
      same_rr a, b, where
      same ao, bo, "#{where} offset suivant"
      same ae, be, "#{where} erreur"

test "parse: messages entiers identiques au code d'origine", ->
  for pi, s in ipairs packets
    for _, is_tcp in ipairs {false, true}
      a, ao, ae = dns.parse s, 1, is_tcp
      b, bo, be = ref_parse s, 1, is_tcp
      where = "parse p#{pi} tcp=#{is_tcp}"
      same_msg a, b, where
      same ao, bo, "#{where} offset suivant"
      same ae, be, "#{where} erreur"

test "noms compressés: un seul table de segments résolue (pas de régression)", ->
  -- Régression ciblée : une réponse dont chaque answer pointe sur le QNAME
  -- doit produire le même nom pointé que la référence, y compris pour une
  -- chaîne de deux pointeurs et pour un pointeur sur un nom vide.
  s = hex2bin resp_hex
  a = dns.parse_rr s, 13 + #hex2bin("076578616d706c6503636f6d0000010001"), 1
  b = ref_parse_rr s, 13 + #hex2bin("076578616d706c6503636f6d0000010001"), 1
  same a.name, b.name, "nom de l'answer compressé"
  -- Pointeur vers un terminateur (nom vide) : les deux doivent rendre "".
  empty_ptr = hex2bin "000101000001000000000000" .. "c010" .. "0000" .. "00010001"
  a2, _, ae2 = dns.parse_rr empty_ptr, 13, 1
  b2, _, be2 = ref_parse_rr empty_ptr, 13, 1
  if a2
    same a2.name, b2.name, "nom vide via pointeur"
  else
    same ae2, be2, "erreur sur nom vide via pointeur"

util.summary "l7/dns_names"
