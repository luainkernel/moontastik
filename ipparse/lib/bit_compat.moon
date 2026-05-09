--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise Operations Compatibility Module
-- This module provides bitwise operations compatible with Lua 5.1 through 5.5.
-- It automatically selects the appropriate bit library based on the Lua version:
-- - LuaJIT/Lua 5.1: Uses the `bit` library
-- - Lua 5.2: Uses the `bit32` library
-- - Lua 5.3+: Uses native bitwise operators
--
-- @module lib.bit_compat

pow2 = (n) ->
  p = 1
  for _ = 1, n
    p *= 2
  p

fallback_lshift = (a, n) ->
  return a if n <= 0
  a * pow2(n)

fallback_rshift = (a, n) ->
  return a if n <= 0
  math.floor((a % 0x100000000) / pow2(n))

normalize = (bit) ->
  bit.lshift = bit.lshift or bit.blshift or fallback_lshift
  bit.rshift = bit.rshift or bit.brshift or fallback_rshift
  bit.arshift = bit.arshift or bit.rshift
  bit

-- Try to load the bit library (LuaJIT/Lua 5.1 / Lunatik variants)
ok, bit = pcall require, "bit"
return normalize(bit) if ok and bit
-- Fall back to bit32 (Lua 5.2)
ok, bit = pcall require, "bit32"
return normalize(bit) if ok and bit
-- Use native operators for Lua 5.3+ (through helper module)
ok, bit = pcall require, "ipparse.lib.bit53"
return normalize(bit) if ok and bit
error "no bitwise compatibility backend available"
