--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Pure-Lua bitwise fallback (32-bit, LuaJIT `bit` semantics).
-- Arithmetic only: no FFI, no `bit`/`bit32`, no Lua 5.3 operators, so it
-- loads under Lua 5.1. Results are signed 32-bit values, exactly like
-- LuaJIT's `bit` library (`bor(0x80000000, 0) == -2147483648`). ipparse's
-- real paths rely on that signedness: fields are masked afterwards, and the
-- QUIC VarInt encoder deliberately avoids the negative int32 produced by
-- `bor(0x80000000, value)`.
--
-- Like `bit` (and `bit53`), `band`, `bor` and `bxor` are variadic and fold
-- left to right; shift counts are masked to 5 bits.
--
-- @module lib.bit_pure
-- @return table Bitwise operations table

TWO32 = 0x100000000
MASK32 = 0xFFFFFFFF
SIGN32 = 0x80000000

pow2 = (n) ->
  p = 1
  p *= 2 for _ = 1, n
  p

--- Normalizes a number to an unsigned 32-bit value.
to_u32 = (n) ->
  math.floor(n % TWO32)

--- Reinterprets an unsigned 32-bit value as a signed 32-bit value.
to_s32 = (u) ->
  return u - TWO32 if u >= SIGN32
  u

and2 = (a, b) ->
  result, weight = 0, 1
  for _ = 1, 32
    result += weight if a % 2 == 1 and b % 2 == 1
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight *= 2
  result

or2 = (a, b) ->
  result, weight = 0, 1
  for _ = 1, 32
    result += weight if a % 2 == 1 or b % 2 == 1
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight *= 2
  result

xor2 = (a, b) ->
  result, weight = 0, 1
  for _ = 1, 32
    result += weight if (a % 2) != (b % 2)
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight *= 2
  result

fold = (op, ...) ->
  n = select("#", ...)
  r = to_u32((...))
  for i = 2, n
    r = op(r, to_u32((select(i, ...))))
  to_s32(r)

bit =
  band: (...) -> fold(and2, ...)
  bor: (...) -> fold(or2, ...)
  bxor: (...) -> fold(xor2, ...)
  bnot: (a) -> to_s32(MASK32 - to_u32(a))
  lshift: (a, n) ->
    n %= 32
    u = to_u32(a)
    return to_s32(u) if n == 0
    -- Keep the product below 2^32 so it stays exactly representable.
    to_s32((u % pow2(32 - n)) * pow2(n))
  rshift: (a, n) ->
    n %= 32
    u = to_u32(a)
    return to_s32(u) if n == 0
    to_s32(math.floor(u / pow2(n)))
  arshift: (a, n) ->
    n %= 32
    s = to_s32(to_u32(a))
    return s if n == 0
    to_s32(math.floor(s / pow2(n)))

return bit
