--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_bit_compat.moon
-- Tests for the bitwise compatibility layer, notably variadic band/bor/bxor

util = require "ipparse.lib.util"
{:test} = util
{ :band, :bor, :bxor, :arshift } = require "ipparse.lib.bit_compat"
-- Test the pure-Lua fallback directly wherever it can run, so it is exercised
-- even when the host has LuaJIT's `bit` or Lua 5.2+'s `bit32`.
-- It is only the last-resort fallback of `bit_compat` (Lua 5.1 without `bit`)
-- and relies on `math.floor`, which the Lua 5.5 kernel runtime lacks: the
-- `bit_pure` cases below therefore only run where `math.floor` exists.
pure = require "ipparse.lib.bit_pure"

test_pure = (name, fn) ->
  test name, fn if math.floor

test "bit_compat: band with 1 argument", ->
  assert band(5) == 5, "band(5) != 5"

test "bit_compat: band with 7 arguments", ->
  assert band(0xFF, 0xFF, 0xFF, 0x3C, 0xFF, 0x1E, 0xFF) == 28, "band of 7 arguments != 28"

test "bit_compat: bxor with 1 argument", ->
  assert bxor(5) == 5, "bxor(5) != 5"

test "bit_compat: bxor with 7 arguments", ->
  assert bxor(0xFF, 0x0F, 0xF0, 0x3C, 0xC3, 0x55, 0xAA) == 0, "bxor of 7 arguments != 0"

test "bit_compat: bor with 1 argument", ->
  assert bor(5) == 5, "bor(5) != 5"

test "bit_compat: bor with 2 arguments", ->
  assert bor(1, 2) == 3, "bor(1,2) != 3"

test "bit_compat: bor with 7 arguments", ->
  assert bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127"

test "bit_compat: bor with 7 TCP flag arguments", ->
  assert bor(0, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01) == 63, "TCP flags != 63"

test "bit_compat: band with 3 arguments", ->
  assert band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28"

test "bit_compat: bxor with 3 arguments", ->
  assert bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51"

test "bit_compat: arshift sign-extends", ->
  assert arshift(-8, 1) == -4, "arshift(-8,1) != -4"
  assert arshift(8, 1) == 4, "arshift(8,1) != 4"

-- Expected values below are hardcoded from LuaJIT's `bit` library, which
-- returns SIGNED 32-bit results (e.g. bit.bor(0x80000000, 0) == -2147483648).
-- ipparse relies on that signedness in the QUIC VarInt encoder, which avoids
-- the negative int32 produced by `bor(0x80000000, value)`.

test_pure "bit_pure: band with 1 argument", ->
  assert pure.band(0xFF) == 255, "band(0xFF) != 255"

test_pure "bit_pure: band with 2 arguments", ->
  assert pure.band(-1, 0xFF) == 255, "band(-1,0xFF) != 255"
  assert pure.band(0xFFFFFFFF, 0xFFFF) == 65535, "band(0xFFFFFFFF,0xFFFF) != 65535"
  assert pure.band(0x80000000, 0x80000000) == -2147483648, "band of bit 31 != -2147483648"

test_pure "bit_pure: band with 3 arguments", ->
  assert pure.band(0xFF, 0x3C, 0x1E) == 28, "band(0xFF,0x3C,0x1E) != 28"

test_pure "bit_pure: bor with 1 argument", ->
  assert pure.bor(5) == 5, "bor(5) != 5"
  assert pure.bor(0x80000000) == -2147483648, "bor(0x80000000) != -2147483648"

test_pure "bit_pure: bor with 2 arguments", ->
  assert pure.bor(1, 2) == 3, "bor(1,2) != 3"
  assert pure.bor(0x80000000, 0) == -2147483648, "bor(0x80000000,0) != -2147483648"
  assert pure.bor(0x80000000, 0xFF) == -2147483393, "bor(0x80000000,0xFF) != -2147483393"

test_pure "bit_pure: bor with 3 arguments", ->
  assert pure.bor(1, 2, 4) == 7, "bor(1,2,4) != 7"

test_pure "bit_pure: bor with 7 arguments", ->
  assert pure.bor(1, 2, 4, 8, 16, 32, 64) == 127, "bor(1,2,4,8,16,32,64) != 127"

test_pure "bit_pure: bxor with 1 argument", ->
  assert pure.bxor(5) == 5, "bxor(5) != 5"

test_pure "bit_pure: bxor with 2 arguments", ->
  assert pure.bxor(0x80000000, 0xFFFFFFFF) == 2147483647, "bxor(0x80000000,0xFFFFFFFF) != 2147483647"
  assert pure.bxor(0x80000000, 0x80000000) == 0, "bxor(0x80000000,0x80000000) != 0"
  assert pure.bxor(-1, 0xFF) == -256, "bxor(-1,0xFF) != -256"

test_pure "bit_pure: bxor with 3 arguments", ->
  assert pure.bxor(0xF0, 0x3C, 0xFF) == 51, "bxor(0xF0,0x3C,0xFF) != 51"

test_pure "bit_pure: bnot", ->
  assert pure.bnot(0) == -1, "bnot(0) != -1"
  assert pure.bnot(0xFFFFFFFF) == 0, "bnot(0xFFFFFFFF) != 0"
  assert pure.bnot(-1) == 0, "bnot(-1) != 0"

test_pure "bit_pure: lshift by 0, 1 and 31 bits", ->
  assert pure.lshift(3, 0) == 3, "lshift(3,0) != 3"
  assert pure.lshift(1, 1) == 2, "lshift(1,1) != 2"
  assert pure.lshift(1, 31) == -2147483648, "lshift(1,31) != -2147483648"

test_pure "bit_pure: lshift masks the shift count to 5 bits", ->
  assert pure.lshift(1, 32) == 1, "lshift(1,32) != 1"
  assert pure.lshift(1, 33) == 2, "lshift(1,33) != 2"

test_pure "bit_pure: rshift by 0, 1 and 31 bits", ->
  assert pure.rshift(3, 0) == 3, "rshift(3,0) != 3"
  assert pure.rshift(0x80000000, 1) == 1073741824, "rshift(0x80000000,1) != 1073741824"
  assert pure.rshift(0x80000000, 31) == 1, "rshift(0x80000000,31) != 1"
  assert pure.rshift(-1, 1) == 2147483647, "rshift(-1,1) != 2147483647"
  assert pure.rshift(0x80000000, 32) == -2147483648, "rshift(0x80000000,32) != -2147483648"

test_pure "bit_pure: arshift sign-extends", ->
  assert pure.arshift(3, 0) == 3, "arshift(3,0) != 3"
  assert pure.arshift(0x80000000, 1) == -1073741824, "arshift(0x80000000,1) != -1073741824"
  assert pure.arshift(-1, 1) == -1, "arshift(-1,1) != -1"
  assert pure.arshift(0x40000000, 1) == 536870912, "arshift(0x40000000,1) != 536870912"

test_pure "bit_pure: IPv6 version/traffic class/flow label round-trip", ->
  vtf = pure.bor(pure.lshift(6, 28), pure.lshift(0x12, 20), 0x34567)
  assert vtf == 1629701479, "vtf != 1629701479"
  assert pure.rshift(vtf, 28) == 6, "version != 6"
  assert pure.band(pure.rshift(vtf, 20), 0xFF) == 18, "traffic class != 18"
  assert pure.band(vtf, 0xFFFFF) == 214375, "flow label != 214375"

-- ─── Backend selection with simulated libraries ────────────────────────────
--
-- These reload `bit_compat` with fake `bit`/`bit32`/`bit53`/`bit_pure`
-- backends registered in `package.preload`. Every touched entry is saved and
-- restored, even when the load raises. The simulation relies on
-- `package.preload` and `math.floor`, so it is skipped on the integer-only
-- kernel runtime (which the module comment in test_lunatik_kernel_portable
-- also excludes: "no simulated package.preload").

backend_keys = {
  "bit"
  "bit32"
  "ipparse.lib.bit53"
  "ipparse.lib.bit_pure"
  "ipparse.lib.bit_compat"
}

load_bit_compat_with = (preloads) ->
  saved_loaded = {}
  saved_preload = {}
  for k in *backend_keys
    saved_loaded[k] = package.loaded[k]
    saved_preload[k] = package.preload[k]
  mod = nil
  ok = false
  err = nil
  ok, err = pcall ->
    for k in *backend_keys
      package.loaded[k] = nil
      package.preload[k] = nil
    for k, v in pairs preloads
      package.preload[k] = if type(v) == "function" then v else -> v
    mod = require "ipparse.lib.bit_compat"
  for k in *backend_keys
    package.loaded[k] = saved_loaded[k]
    package.preload[k] = saved_preload[k]
  unless ok
    error err, 0
  mod

pow2_test = (n) ->
  p = 1
  for _ = 1, n
    p *= 2
  p

-- Backend exposing the Lua 5.1 `blshift`/`brshift` names.
fake_named = {
  blshift: (a, n) -> if n <= 0 then a else a * pow2_test(n)
  brshift: (a, n) -> if n <= 0 then a else math.floor(a / pow2_test(n))
}

-- Sentinel backends: distinct return values prove which one was selected.
fake32 = {
  blshift: (a, n) -> 111
  brshift: (a, n) -> 222
}
fake53 = {
  lshift: (a, n) -> 333
  rshift: (a, n) -> 444
}
fake_pure = {
  blshift: (a, n) -> 555
  brshift: (a, n) -> 666
}
bad_backend = -> error "backend unavailable"

userspace_backends = package and package.loaded and package.preload and math.floor

test_backends = (name, fn) ->
  if userspace_backends
    test name, fn

test_backends "bit_compat: fallback shifts when 'bit' lacks shifts", ->
  m = load_bit_compat_with { ["bit"]: {} }
  assert m.lshift(3, 2) == 12, "lshift(3,2) != 12"
  assert m.lshift(3, 0) == 3, "lshift by 0 must be identity"
  assert m.lshift(3, -2) == 3, "lshift by a negative count must be identity"
  assert m.rshift(8, 2) == 2, "rshift(8,2) != 2"
  assert m.rshift(8, 0) == 8, "rshift by 0 must be identity"
  assert m.rshift(8, -1) == 8, "rshift by a negative count must be identity"
  assert m.rshift(0x100000004, 2) == 1, "rshift must mask its input to 32 bits"
  assert m.arshift == m.rshift, "arshift should alias rshift"
  assert m.lshift(1, 4) == 16, "lshift(1,4) != 16"

test_backends "bit_compat: blshift/brshift preferred over fallback", ->
  m = load_bit_compat_with { ["bit"]: fake_named }
  assert m.lshift(2, 3) == 16, "lshift(2,3) != 16"
  assert m.rshift(32, 3) == 4, "rshift(32,3) != 4"
  assert m.arshift == m.rshift, "arshift should alias rshift"

test_backends "bit_compat: bit32 backend selection", ->
  m = load_bit_compat_with { ["bit32"]: fake32 }
  assert m.lshift(1, 1) == 111, "bit32 backend not selected for lshift"
  assert m.rshift(1, 1) == 222, "bit32 backend not selected for rshift"
  assert m.arshift == m.rshift, "arshift should alias rshift"

test_backends "bit_compat: bit53 backend selection", ->
  m = load_bit_compat_with { ["ipparse.lib.bit53"]: fake53 }
  assert m.lshift(1, 1) == 333, "bit53 backend not selected for lshift"
  assert m.rshift(1, 1) == 444, "bit53 backend not selected for rshift"

test_backends "bit_compat: bit_pure last-resort backend selection", ->
  m = load_bit_compat_with {
    ["bit"]: bad_backend
    ["bit32"]: bad_backend
    ["ipparse.lib.bit53"]: bad_backend
    ["ipparse.lib.bit_pure"]: fake_pure
  }
  assert m.lshift(1, 1) == 555, "bit_pure backend not selected for lshift"
  assert m.rshift(1, 1) == 666, "bit_pure backend not selected for rshift"

test_backends "bit_compat: no backend raises", ->
  ok, err = pcall load_bit_compat_with, {
    ["bit"]: bad_backend
    ["bit32"]: bad_backend
    ["ipparse.lib.bit53"]: bad_backend
    ["ipparse.lib.bit_pure"]: bad_backend
  }
  assert not ok, "loading with no backend should raise"
  assert (tostring(err)\match "no bitwise compatibility backend"),
    "unexpected error: #{tostring err}"

util.summary "bit_compat"
