--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise operations compatibility layer (Lua 5.3 style).
-- This module provides Lua 5.3-style bitwise operations using the native
-- operators of Lua 5.3 and later.
-- Like LuaJIT's `bit` library, `band`, `bor` and `bxor` are variadic: `bor(a)`
-- returns `a`, and operations fold left to right over their arguments.
-- MoonScript parses `~` ambiguously, so XOR is expressed using boolean identities.
--
-- @module lib.bit53
-- @return table Bitwise operations table

bit =
  band: (a, b, c, ...) ->
    if c == nil
      if b == nil
        a
      else
        a & b
    else
      r = a & b & c
      n = select "#", ...
      for i = 1, n
        r &= (select i, ...)
      r
  bor: (a, b, c, ...) ->
    if c == nil
      if b == nil
        a
      else
        a | b
    else
      r = a | b | c
      n = select "#", ...
      for i = 1, n
        r |= (select i, ...)
      r
  -- MoonScript parses `a ~ b` ambiguously; express XOR with identities.
  bxor: (a, b, c, ...) ->
    if c == nil
      if b == nil
        a
      else
        (a | b) & (~(a & b))
    else
      r = (a | b) & (~(a & b))
      r = (r | c) & (~(r & c))
      n = select "#", ...
      for i = 1, n
        v = select i, ...
        r = (r | v) & (~(r & v))
      r
  bnot: (a) -> ~a
  lshift: (a, n) -> a << n
  rshift: (a, n) -> a >> n
  arshift: (a, n) -> if a >= 0 then a >> n else ~((~a) >> n)

return bit
