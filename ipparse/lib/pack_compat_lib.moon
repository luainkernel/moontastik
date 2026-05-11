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
read_uint = (s, offset, size, le) ->
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

pack = (fmt, ...) ->
  args   = {...}
  argi   = 1
  parts  = {}

  iter = parse_format fmt
  opt, count, le, align = iter!

  while opt != nil
    switch opt

      when "b"   -- int8
        v   = args[argi]
        argi += 1
        v   = v % 256
        parts[#parts+1] = string.char v

      when "B"   -- uint8
        v = args[argi]
        argi += 1
        parts[#parts+1] = string.char(v % 256)

      when "h"   -- int16
        v = args[argi]
        argi += 1
        uv = v % 65536
        if le
          parts[#parts+1] = string.char(uv % 256, math.floor(uv/256) % 256)
        else
          parts[#parts+1] = string.char(math.floor(uv/256) % 256, uv % 256)

      when "H"   -- uint16
        v = args[argi]
        argi += 1
        uv = v % 65536
        if le
          parts[#parts+1] = string.char(uv % 256, math.floor(uv/256) % 256)
        else
          parts[#parts+1] = string.char(math.floor(uv/256) % 256, uv % 256)

      when "i", "I"   -- int/uint N octets (défaut 4)
        sz = count or 4
        v  = args[argi]
        argi += 1
        buf = ffi.new "uint8_t[?]", sz
        write_uint buf, 0, v, sz, le
        parts[#parts+1] = ffi.string buf, sz

      when "l", "L", "j", "J", "T"   -- 64 bits
        v   = args[argi]
        argi += 1
        buf = ffi.new "uint8_t[8]"
        write_uint buf, 0, v, 8, le
        parts[#parts+1] = ffi.string buf, 8

      when "f"   -- float 32
        v = args[argi]
        argi += 1
        bytes = float_to_bytes v, le
        parts[#parts+1] = string.char tunpack bytes

      when "d", "n"   -- double 64
        v = args[argi]
        argi += 1
        bytes = double_to_bytes v, le
        parts[#parts+1] = string.char tunpack bytes

      when "c"   -- chaîne de longueur fixe
        sz = count or 1
        v  = args[argi]
        argi += 1
        if #v < sz
          parts[#parts+1] = v .. string.rep "\0", sz - #v
        else
          parts[#parts+1] = v\sub 1, sz

      when "s"   -- chaîne préfixée par une longueur (size_t = 8 octets ici)
        sz  = count or 8
        v   = args[argi]
        argi += 1
        buf = ffi.new "uint8_t[?]", sz
        write_uint buf, 0, #v, sz, le
        parts[#parts+1] = ffi.string(buf, sz) .. v

      when "z"   -- chaîne null-terminated
        v = args[argi]
        argi += 1
        parts[#parts+1] = v .. "\0"

      when "x"   -- padding (un octet nul)
        parts[#parts+1] = "\0"

      when "X"   -- alignement (pas d'octet émis dans ce contexte simplifié)
        nil -- no-op

    opt, count, le, align = iter!

  table.concat parts

-- ─── string.unpack ───────────────────────────────────────────────────────────

unpack = (fmt, s, pos) ->
  pos  = (pos or 1) - 1   -- on travaille en 0-based en interne
  results = {}

  iter = parse_format fmt
  opt, count, le, align = iter!

  while opt != nil
    switch opt

      when "b"   -- int8
        v = string.byte s, pos + 1
        v = to_signed v, 1
        results[#results+1] = v
        pos += 1

      when "B"   -- uint8
        results[#results+1] = string.byte s, pos + 1
        pos += 1

      when "h"   -- int16
        uv = read_uint s, pos, 2, le
        results[#results+1] = to_signed uv, 2
        pos += 2

      when "H"   -- uint16
        results[#results+1] = tonumber read_uint s, pos, 2, le
        pos += 2

      when "i"   -- intN signé
        sz = count or 4
        uv = read_uint s, pos, sz, le
        results[#results+1] = to_signed uv, sz
        pos += sz

      when "I"   -- uintN non signé
        sz = count or 4
        results[#results+1] = tonumber read_uint s, pos, sz, le
        pos += sz

      when "l"   -- int64 signé
        uv = read_uint s, pos, 8, le
        results[#results+1] = tonumber ffi.cast "int64_t", uv
        pos += 8

      when "L", "J", "T"   -- uint64
        results[#results+1] = tonumber read_uint s, pos, 8, le
        pos += 8

      when "j"   -- lua_Integer (int64 signé)
        uv = read_uint s, pos, 8, le
        results[#results+1] = tonumber ffi.cast "int64_t", uv
        pos += 8

      when "f"   -- float 32
        results[#results+1] = bytes_to_float s, pos, le
        pos += 4

      when "d", "n"   -- double 64
        results[#results+1] = bytes_to_double s, pos, le
        pos += 8

      when "c"   -- chaîne de longueur fixe
        sz = count or 1
        results[#results+1] = s\sub pos + 1, pos + sz
        pos += sz

      when "s"   -- chaîne préfixée longueur
        sz  = count or 8
        len = tonumber read_uint s, pos, sz, le
        pos += sz
        results[#results+1] = s\sub pos + 1, pos + len
        pos += len

      when "z"   -- chaîne null-terminated
        nul = s\find "\0", pos + 1, true
        if not nul
          error "string.unpack 'z' : pas de \\0 trouvé"
        results[#results+1] = s\sub pos + 1, nul - 1
        pos = nul   -- avance juste après le \0

      when "x"   -- padding (ignore 1 octet)
        pos += 1

      when "X"   -- alignement (no-op simplifié)
        nil -- no-op

    opt, count, le, align = iter!

  -- Ajoute la position suivante (1-based) comme dernier résultat
  results[#results+1] = pos + 1
  tunpack results

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

-- ─── Injection dans string.* ─────────────────────────────────────────────────

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
