--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Memoization helpers.
-- Split out of `ipparse.fun` so the other primitives can be loaded without
-- this module.
-- @module fun.memo

unpack or= table.unpack

--- Creates a memoized version of a single-argument function.
-- The cache uses the input argument as the key.
-- If the argument is `nil` or not provided, the original function is called directly without caching.
-- The cache is a weak table on purpose: entries may be dropped by the garbage collector, trading recomputation for bounded memory.
-- @treturn function The memoized function.
-- @usage
-- -- The memoized function takes:
-- -- @tparam any x The argument to the original function.
-- -- @treturn ...any The result from the original function.
-- @usage
-- local memo_expensive_calc = fun.memo(expensive_calc)
-- local result1 = memo_expensive_calc(5) -- expensive_calc is called
-- local result2 = memo_expensive_calc(5) -- result is retrieved from cache
memo = =>
  tmp = __mode: "kv"
  setmetatable tmp, tmp
  (x) ->
    return @(x) if x == nil  -- nil cannot be a table key: bypass the cache
    r = tmp[x] or {@ x}
    tmp[x] = r
    unpack r

--- Creates a memoized version of a multi-argument function.
-- The cache is hierarchical, using arguments as keys at successive levels.
-- `nil` arguments are handled by using a special internal `_nil` placeholder.
-- The cache is a weak table on purpose: entries may be dropped by the garbage collector, trading recomputation for bounded memory.
-- @treturn function The memoized function.
-- @usage
-- -- The memoized function takes:
-- -- @tparam ...any ... Arguments to the original function.
-- -- @treturn ...any The result from the original function.
memoN = =>
  _nil = {}
  tmp = __mode: "kv"
  setmetatable tmp, tmp
  (...) ->
    t, s = tmp, select "#", ...
    levels = {s, ...}
    local ref, r
    for i = 1, s+1
      ref = levels[i]
      ref = _nil if ref == nil
      r = t[ref]
      if i <= s
        r or= setmetatable {}, tmp
        t[ref] = r
        t = r
    if r == nil
      r = {@ ...}
      t[ref] = r
    unpack r

{:memo, :memoN}
