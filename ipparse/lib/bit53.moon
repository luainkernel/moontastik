--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise operations compatibility layer (Lua 5.3 style).
-- This module provides Lua 5.3-style bitwise operations using LuaJIT's native operators.
-- MoonScript parses `~` ambiguously, so XOR is expressed using boolean identities.
--
-- @module lib.bit53
-- @return table Bitwise operations table

bit =
  band: (a, b) -> a & b
  bor: (a, b) -> a | b
  -- MoonScript parses `a ~ b` ambiguously; express XOR with identities.
  bxor: (a, b) -> (a | b) & (~(a & b))
  bnot: (a) -> ~a
  lshift: (a, n) -> a << n
  rshift: (a, n) -> a >> n
  arshift: (a, n) -> a >> n

return bit
