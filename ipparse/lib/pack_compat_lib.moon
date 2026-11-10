--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Binary pack/unpack implementation for LuaJIT (Lua 5.1 compatibility).
-- This module provides a pure Lua (with FFI) implementation of Lua 5.3's string.pack,
-- string.unpack, and string.packsize for use on LuaJIT and Lua 5.1.
--
-- The implementation is compatible with the Lua 5.3+ specification and uses FFI
-- for efficient low-level operations without requiring compilation.
--
-- @module lib.pack_compat_lib
-- @return table Module with pack, unpack, packsize, and inject functions

-- string_compat.moon
-- Implémentation de string.pack / string.unpack / string.packsize pour LuaJIT
-- Utilise FFI pour les opérations bas niveau, sans étape de compilation.
-- Compatible avec la spécification Lua 5.3+

return string if string.unpack

tunpack = unpack or table.unpack

ffi = require "ffi"

ffi.cdef [[
  void *memcpy(void *dest, const void *src, size_t n);
  void *memset(void *s, int c, size_t n);
]]

-- ─── Détection de l'endianness native ───────────────────────────────────────

NATIVE_LE = do
  probe = ffi.new "uint16_t[1]", 0x0102
  pb    = ffi.cast "uint8_t *", probe
  pb[0] == 0x02   -- little-endian si l'octet de poids faible est en premier

-- ─── Utilitaires ────────────────────────────────────────────────────────────

-- Lit un entier non signé depuis une chaîne (offset 0-based, size octets)
-- Comme string.unpack de Lua 5.3, lève une erreur explicite sur chaîne tronquée.
read_uint = (s, offset, size, le) ->
  error "data string too short" if offset + size > #s
  if size == 1
    return string.byte s, offset + 1
  if size == 2
    a, b = string.byte s, offset + 1, offset + 2
    return le and (b * 256 + a) or (a * 256 + b)
  if size == 4
    a, b, c, d = string.byte s, offset + 1, offset + 4
    return le and (d * 16777216 + c * 65536 + b * 256 + a) or (a * 16777216 + b * 65536 + c * 256 + d)
  val = ffi.cast "uint64_t", 0
  if le
    for i = size - 1, 0, -1
      val = val * 256 + string.byte(s, offset + i + 1)
  else
    for i = 0, size - 1
      val = val * 256 + string.byte(s, offset + i + 1)
  val

-- Écrit un entier non signé vers un buffer ffi uint8_t* (offset 0-based)
write_uint = (buf, offset, val, size, le) ->
  v = ffi.cast "uint64_t", val
  if le
    for i = 0, size - 1
      buf[offset + i] = tonumber(v % 256)
      v = v / 256
  else
    for i = size - 1, 0, -1
      buf[offset + i] = tonumber(v % 256)
      v = v / 256

-- Conversion unsigned → signed (complément à deux)
to_signed = (val, size) ->
  uval = tonumber(ffi.cast "uint64_t", val)
  bits = size * 8
  limit = 2 ^ (bits - 1)
  if uval >= limit
    uval - 2 ^ bits
  else
    uval

-- ─── Parseur de format ───────────────────────────────────────────────────────

-- Renvoie un itérateur sur {option, count} depuis une chaîne de format.
-- option : le caractère de format
-- count  : le nombre de répétitions (nil si non applicable)
parse_format = (fmt) ->
  i     = 1
  le    = NATIVE_LE   -- endianness courante
  align = true        -- alignement actif ?

  ->
    while i <= #fmt
      c = fmt\sub i, i
      i += 1

      -- Modificateurs d'endianness / alignement
      if c == ">"
        le = false
        align = false
        continue
      if c == "<"
        le = true
        align = false
        continue
      if c == "="
        le = NATIVE_LE
        align = false
        continue
      if c == "!" then
        -- "!n" : alignement sur n octets (on ignore la valeur ici)
        if i <= #fmt and fmt\sub(i,i)\match "%d"
          i += 1   -- skip digit
        align = true
        continue
      if c == " "
        continue

      -- Lecture d'un count optionnel
      count = nil
      if i <= #fmt
        nc = fmt\sub i, i
        if nc\match "%d"
          count = tonumber nc
          i += 1
          while i <= #fmt and fmt\sub(i,i)\match "%d"
            count = count * 10 + tonumber(fmt\sub i, i)
            i += 1

      return c, count, le, align

    nil  -- fin

-- ─── Taille d'un élément de format ──────────────────────────────────────────

element_size = (opt, count) ->
  switch opt
    when "b", "B"        then 1
    when "h", "H"        then 2
    when "i", "I"        then count or 4
    when "l", "L"        then 8
    when "j", "J"        then 8   -- lua_Integer / lua_Unsigned
    when "T"             then 8   -- size_t
    when "f"             then 4
    when "d", "n"        then 8
    when "e"             then 2   -- half-float (lecture seule utile)
    when "c"             then count or 1
    when "s"             then nil  -- variable
    when "z"             then nil  -- variable (null-terminated)
    when "x"             then 1   -- padding
    when "X"             then 0   -- alignement seulement
    else
      error "option de format inconnue : '#{opt}'"

-- ─── string.packsize ─────────────────────────────────────────────────────────

packsize = (fmt) ->
  total = 0
  iter  = parse_format fmt
  opt, count, le, align = iter!
  while opt != nil
    sz = element_size opt, count
    if sz == nil
      error "string.packsize : format '#{opt}' a une taille variable"
    total += sz
    opt, count, le, align = iter!
  total

-- ─── Cache de formats pré-parsés ────────────────────────────────────────────

-- Table de cache : fmt (string) → tableau de {opt, count, le}
_fmt_cache = {}

-- Matérialise le résultat de parse_format en tableau et le met en cache.
-- Doit être défini après parse_format pour que la closure capture la bonne locale.
parse_format_to_ops = (fmt) ->
  ops = {}
  iter = parse_format fmt
  opt, count, le, align = iter!
  while opt != nil
    ops[#ops+1] = {opt, count, le}
    opt, count, le, align = iter!
  _fmt_cache[fmt] = ops
  ops

-- ─── Encodage IEEE 754 double ────────────────────────────────────────────────

double_to_bytes = (n, le) ->
  buf = ffi.new "double[1]", n
  b   = ffi.cast "uint8_t *", buf
  bytes = {b[i] for i = 0, 7}
  if not le
    bytes = {bytes[8], bytes[7], bytes[6], bytes[5],
             bytes[4], bytes[3], bytes[2], bytes[1]}
  bytes

bytes_to_double = (s, offset, le) ->
  buf = ffi.new "uint8_t[8]"
  if le
    for i = 0, 7
      buf[i] = string.byte s, offset + i + 1
  else
    for i = 0, 7
      buf[i] = string.byte s, offset + 7 - i + 1
  d = ffi.cast "double *", buf
  d[0]

float_to_bytes = (n, le) ->
  buf = ffi.new "float[1]", n
  b   = ffi.cast "uint8_t *", buf
  bytes = {b[i] for i = 0, 3}
  if not le
    bytes = {bytes[4], bytes[3], bytes[2], bytes[1]}
  bytes

bytes_to_float = (s, offset, le) ->
  buf = ffi.new "uint8_t[4]"
  if le
    for i = 0, 3
      buf[i] = string.byte s, offset + i + 1
  else
    for i = 0, 3
      buf[i] = string.byte s, offset + 3 - i + 1
  f = ffi.cast "float *", buf
  tonumber f[0]

-- ─── string.pack ─────────────────────────────────────────────────────────────

-- Tampon d'octets partagé au niveau du module. `pack` n'appelle aucun callback
-- utilisateur pendant la construction : il n'est donc pas réentrant, ce qui est
-- acceptable ici. Les writers écrivent dans _buf[n+1 .. n+size] et renvoient le
-- nouvel index (0-based), sans allouer de chaîne.
_buf = {}

-- Convertit _buf[1..n] en chaîne, par morceaux de 4096 max pour rester sous la
-- limite pratique de `unpack`/`string.char`. Fonction de module (et non closure
-- locale à pack) pour que LuaJIT puisse compiler le chemin rapide : créer une
-- closure par appel (bytecode FNEW) est NYI et annule la compilation du trace.
buf_string = (buf, n) ->
  if n <= 4096
    string.char tunpack buf, 1, n
  else
    out = {}
    i = 0
    while i < n
      len = math.min 4096, n - i
      out[#out+1] = string.char tunpack buf, i + 1, i + len
      i += len
    table.concat out

-- Ajoute `s` à `parts` (crée la liste au besoin) et renvoie la liste.
append_string = (parts, s) ->
  parts = {} unless parts
  parts[#parts+1] = s
  parts

-- Construit un writer d'entier non signé de `sz` octets : écrit les octets dans
-- `buf` à partir de l'index `n` et renvoie `n + sz`.
-- Les tailles 1 à 4 sont déroulées, 5-6 utilisent une petite boucle, et au-delà
-- de 6 octets on passe par uint64_t pour conserver la précision actuelle.
make_uint = (sz, le) ->
  if sz == 1
    (buf, n, v) ->
      buf[n + 1] = v % 256
      n + 1
  elseif sz == 2
    if le
      (buf, n, v) ->
        u = v % 65536
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        n + 2
    else
      (buf, n, v) ->
        u = v % 65536
        buf[n + 1] = math.floor(u / 256) % 256
        buf[n + 2] = u % 256
        n + 2
  elseif sz == 3
    mod = 16777216
    if le
      (buf, n, v) ->
        u = v % mod
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = math.floor(u / 65536) % 256
        n + 3
    else
      (buf, n, v) ->
        u = v % mod
        buf[n + 1] = math.floor(u / 65536) % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = u % 256
        n + 3
  elseif sz == 4
    mod = 4294967296
    if le
      (buf, n, v) ->
        u = v % mod
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = math.floor(u / 65536) % 256
        buf[n + 4] = math.floor(u / 16777216) % 256
        n + 4
    else
      (buf, n, v) ->
        u = v % mod
        buf[n + 1] = math.floor(u / 16777216) % 256
        buf[n + 2] = math.floor(u / 65536) % 256
        buf[n + 3] = math.floor(u / 256) % 256
        buf[n + 4] = u % 256
        n + 4
  elseif sz <= 6
    mod = 2 ^ (8 * sz)
    if le
      (buf, n, v) ->
        u = v % mod
        for k = 1, sz
          buf[n + k] = u % 256
          u = math.floor(u / 256)
        n + sz
    else
      (buf, n, v) ->
        u = v % mod
        for k = sz, 1, -1
          buf[n + k] = u % 256
          u = math.floor(u / 256)
        n + sz
  else
    if le
      (buf, n, v) ->
        u = ffi.cast "uint64_t", v
        for k = 1, sz
          buf[n + k] = tonumber(u % 256)
          u = u / 256
        n + sz
    else
      (buf, n, v) ->
        u = ffi.cast "uint64_t", v
        for k = sz, 1, -1
          buf[n + k] = tonumber(u % 256)
          u = u / 256
        n + sz

make_float = (le) ->
  (v) -> string.char(tunpack(float_to_bytes(v, le)))

make_double = (le) ->
  (v) -> string.char(tunpack(double_to_bytes(v, le)))

make_c = (sz) ->
  (v) ->
    if #v < sz
      v .. string.rep "\0", sz - #v
    else
      v\sub 1, sz

-- Choisit l'encodeur d'une option au moment de la compilation du format.
pack_op = (opt, count, le) ->
  switch opt

    when "b", "B"   -- int8 / uint8
      { consume: true, write: make_uint(1, le) }

    when "h", "H"   -- int16 / uint16
      { consume: true, write: make_uint(2, le) }

    when "i", "I"   -- int/uint N octets (défaut 4)
      { consume: true, write: make_uint((count or 4), le) }

    when "l", "L", "j", "J", "T"   -- 64 bits
      { consume: true, write: make_uint(8, le) }

    when "f"   -- float 32
      { consume: true, emit: make_float le }

    when "d", "n"   -- double 64
      { consume: true, emit: make_double le }

    when "c"   -- chaîne de longueur fixe
      { consume: true, emit: make_c(count or 1) }

    when "s"   -- chaîne préfixée longueur (size_t = 8 octets par défaut)
      { consume: true, write_len: make_uint((count or 8), le), emit: (v) -> v }

    when "z"   -- chaîne null-terminated
      { consume: true, emit: (v) -> v .. "\0" }

    when "x"   -- padding (un octet nul)
      { consume: false, write: (buf, n) ->
        buf[n + 1] = 0
        n + 1 }

    else       -- "X" (alignement) et options inconnues : no-op
      { consume: false, write: (buf, n) -> n }

-- Cache des formats compilés en liste d'encodeurs : fmt → plan.
_pack_cache = {}

compile_pack = (fmt) ->
  plan = {}
  consumed = 0
  iter = parse_format fmt
  opt, count, le = iter!
  while opt != nil
    op = pack_op opt, count, le
    plan[#plan+1] = op
    consumed += 1 if op.consume
    opt, count, le = iter!
  plan.count = consumed
  _pack_cache[fmt] = plan
  plan

-- `a1`..`a8` couvrent la grande majorité des formats sans vararg ni `select`
-- dans la boucle ; au-delà de 8 valeurs consommées, on bascule sur le chemin
-- générique qui collecte le vararg une seule fois.
pack = (fmt, a1, a2, a3, a4, a5, a6, a7, a8, ...) ->
  plan = _pack_cache[fmt] or compile_pack(fmt)
  args = nil
  if plan.count > 8
    args = {a1, a2, a3, a4, a5, a6, a7, a8, ...}
  else
    args = {a1, a2, a3, a4, a5, a6, a7, a8}

  n     = 0
  parts = nil

  argi = 1
  for j = 1, #plan
    op = plan[j]
    if op.write
      if op.consume
        n = op.write _buf, n, args[argi]
        argi += 1
      else
        n = op.write _buf, n
    else
      v = args[argi]
      argi += 1
      if op.write_len
        n = op.write_len _buf, n, #v
      if n > 0
        parts = append_string parts, buf_string(_buf, n)
        n = 0
      parts = append_string parts, op.emit v

  if parts
    if n > 0
      parts = append_string parts, buf_string(_buf, n)
    table.concat parts
  else
    buf_string _buf, n

-- ─── string.unpack ───────────────────────────────────────────────────────────

-- Buffer de résultats réutilisé : unpack n'est pas ré-entrant, donc safe.
_results = {}

unpack = (fmt, s, pos) ->
  pos  = (pos or 1) - 1   -- on travaille en 0-based en interne
  n    = 0
  ops  = _fmt_cache[fmt] or parse_format_to_ops(fmt)

  for j = 1, #ops
    {opt, count, le} = ops[j]
    switch opt

      when "b"   -- int8
        v = string.byte s, pos + 1
        n += 1
        _results[n] = to_signed v, 1
        pos += 1

      when "B"   -- uint8
        n += 1
        _results[n] = string.byte s, pos + 1
        pos += 1

      when "h"   -- int16
        uv = read_uint s, pos, 2, le
        n += 1
        _results[n] = to_signed uv, 2
        pos += 2

      when "H"   -- uint16
        n += 1
        _results[n] = tonumber read_uint s, pos, 2, le
        pos += 2

      when "i"   -- intN signé
        sz = count or 4
        uv = read_uint s, pos, sz, le
        n += 1
        _results[n] = to_signed uv, sz
        pos += sz

      when "I"   -- uintN non signé
        sz = count or 4
        n += 1
        _results[n] = tonumber read_uint s, pos, sz, le
        pos += sz

      when "l"   -- int64 signé
        uv = read_uint s, pos, 8, le
        n += 1
        _results[n] = tonumber ffi.cast "int64_t", uv
        pos += 8

      when "L", "J", "T"   -- uint64
        n += 1
        _results[n] = tonumber read_uint s, pos, 8, le
        pos += 8

      when "j"   -- lua_Integer (int64 signé)
        uv = read_uint s, pos, 8, le
        n += 1
        _results[n] = tonumber ffi.cast "int64_t", uv
        pos += 8

      when "f"   -- float 32
        n += 1
        _results[n] = bytes_to_float s, pos, le
        pos += 4

      when "d", "n"   -- double 64
        n += 1
        _results[n] = bytes_to_double s, pos, le
        pos += 8

      when "c"   -- chaîne de longueur fixe
        sz = count or 1
        n += 1
        _results[n] = s\sub pos + 1, pos + sz
        pos += sz

      when "s"   -- chaîne préfixée longueur
        sz  = count or 8
        len = tonumber read_uint s, pos, sz, le
        pos += sz
        n += 1
        _results[n] = s\sub pos + 1, pos + len
        pos += len

      when "z"   -- chaîne null-terminated
        nul = s\find "\0", pos + 1, true
        if not nul
          error "string.unpack 'z' : pas de \\0 trouvé"
        n += 1
        _results[n] = s\sub pos + 1, nul - 1
        pos = nul   -- avance juste après le \0

      when "x"   -- padding (ignore 1 octet)
        pos += 1

      when "X"   -- alignement (no-op simplifié)
        nil -- no-op

  -- Ajoute la position suivante (1-based) comme dernier résultat
  n += 1
  _results[n] = pos + 1
  tunpack _results, 1, n

-- ─── Injection dans string.* ─────────────────────────────────────────────────

--- Injects pack/unpack functions into the global string table.
-- This makes string.pack, string.unpack, and string.packsize available globally.
inject = ->
  string.pack     = pack
  string.unpack   = unpack
  string.packsize = packsize

-- ─── Export ──────────────────────────────────────────────────────────────────

setmetatable {
  :pack
  :unpack
  :packsize
  :inject
}, __index: string
