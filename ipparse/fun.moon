--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Small library for basic functional programming primitives.
-- Provides utilities for memoization, iteration, and other functional constructs.
-- This module is a thin facade over `fun.tables`, `fun.memo`, `fun.iter` and
-- `fun.protected`; it re-exports their functions unchanged. Protocol modules
-- that only need `bidirectional`/`zero_indexed` should require
-- `ipparse.fun.tables` directly to keep the `require` chain shallow.
-- @module fun

{:bidirectional, :zero_indexed, :opairs} = require "ipparse.fun.tables"
{:memo, :memoN} = require "ipparse.fun.memo"
{:iter, :wrap, :generate, :range} = require "ipparse.fun.iter"
protected_mod = require "ipparse.fun.protected"
{:protected} = protected_mod

--- The main export table for the `fun` module.
-- It provides direct access to functions like `memo`, `range`, etc.
-- Additionally, it has a special `__index` metamethod that allows
-- `iter` methods (like `map`, `filter`, `reduce`) to be called directly
-- on the `fun` module itself if the first argument is a table (or something `iter` can wrap).
-- This provides a convenient shortcut.
--
-- `__newindex` forwards `leak_debug` writes to `fun.protected`, so
-- `fun.leak_debug = true` keeps controlling `fun.protected`; any other key is
-- stored directly on the facade. Conversely, reading `leak_debug` returns the
-- value held by `fun.protected`.
-- @usage
-- -- When using methods like fun.map(tbl, fn):
-- -- The __index metamethod creates a wrapper function. This wrapper:
--  The table or iterator being operated on.
-- -- @tparam ...any ... Arguments for the specific iterator method (e.g., the mapping function for `map`).
-- -- @treturn any The result of the iterator method (e.g., a new `fun.iterator` for `map`, a value for `reduce`).
-- local fun = require "fun"
-- local doubled = fun.map({1,2,3}, (x) -> x * 2) -- equivalent to fun.iter({1,2,3})\map(...)
-- local sum = fun.reduce({1,2,3}, ((acc,v) -> acc + v), 0) -- equivalent to fun.iter({1,2,3})\reduce(...)
_ = {
  :bidirectional, :memo, :memoN, :iter, :wrap, :range, :opairs, :generate, :zero_indexed
  :protected
  __index: (_, k) ->
    return protected_mod.leak_debug if k == "leak_debug"
    fn = (...) =>
      o = (type(@) == 'table' and iter or wrap) @
      o[k] o, ...
    rawset _, k, fn
    fn
  __newindex: (_, k, v) ->
    if k == "leak_debug"
      protected_mod.leak_debug = v
    else
      rawset _, k, v
}

setmetatable _, _
