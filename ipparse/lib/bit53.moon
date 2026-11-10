--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise operations compatibility layer (Lua 5.3 style).
-- This module provides Lua 5.3-style bitwise operations using LuaJIT's native operators.
-- Like LuaJIT's `bit` library, `band`, `bor` and `bxor` are variadic: `bor(a)`
-- returns `a`, and operations fold left to right over their arguments.
-- MoonScript parses `~` ambiguously, so XOR is expressed using boolean identities.
--
-- @module lib.bit53
-- @return table Bitwise operations table

bit =
  band: (...) ->
    n = select "#", ...
    return ... if n <= 1
    a, b = ...
    return a & b if n == 2
    r = a
    for i = 2, n
      r &= (select i, ...)
    r
  bor: (...) ->
    n = select "#", ...
    return ... if n <= 1
    a, b = ...
    return a | b if n == 2
    r = a
    for i = 2, n
      r |= (select i, ...)
    r
  -- MoonScript parses `a ~ b` ambiguously; express XOR with identities.
  bxor: (...) ->
    n = select "#", ...
    return ... if n <= 1
    a, b = ...
    return (a | b) & (~(a & b)) if n == 2
    r = a
    for i = 2, n
      v = select i, ...
      r = (r | v) & (~(r & v))
    r
  bnot: (a) -> ~a
  lshift: (a, n) -> a << n
  rshift: (a, n) -> a >> n
  arshift: (a, n) -> a >> n

return bit
