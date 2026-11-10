--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise Operations Compatibility Module
-- This module provides bitwise operations compatible with Lua 5.1 through 5.5.
-- It automatically selects the appropriate bit library based on the Lua version:
-- - Lua 5.3+/Lunatik kernel: Uses native bitwise operators (`ipparse.lib.bit53`)
-- - LuaJIT/Lua 5.1: Uses the `bit` library
-- - Lua 5.2: Uses the `bit32` library
-- - Last resort: the pure-Lua arithmetic `ipparse.lib.bit_pure`
--
-- The native backend is chosen by capability, before any `pcall`: a failed
-- load of `ipparse.lib.bit53` (notably a C stack overflow in the kernel) must
-- propagate unchanged instead of being masked by the generic error.
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

-- True when values are native 64-bit integers (Lua 5.3+/Lunatik kernel).
-- Same predicate as ipparse/l4/quic/frames.moon; false on LuaJIT and Lua 5.1.
native_int = math.floor == nil or math.type ~= nil

-- Use native operators for Lua 5.3+ (through helper module). Loaded without
-- `pcall` so that a load failure (e.g. a C stack overflow in the kernel)
-- propagates with its real message. `bit53` cannot even be parsed on
-- LuaJIT/Lua 5.1 (native `&`, `|`, `~`, `<<`, `>>`), hence the guard.
return normalize require "ipparse.lib.bit53" if native_int

-- Try to load the bit library (LuaJIT/Lua 5.1)
err = nil
ok, bit = pcall require, "bit"
return normalize(bit) if ok and bit
err = bit
-- Fall back to bit32 (Lua 5.2)
ok, bit = pcall require, "bit32"
return normalize(bit) if ok and bit
err = bit
-- Pure-Lua arithmetic fallback (Lua 5.1 without LuaJIT's `bit`)
ok, bit = pcall require, "ipparse.lib.bit_pure"
return normalize(bit) if ok and bit
err = bit
error "no bitwise compatibility backend available (last error: #{err})"
