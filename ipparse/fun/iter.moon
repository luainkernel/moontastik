--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Iterator helpers.
-- Split out of `ipparse.fun` so the other primitives can be loaded without
-- this module.
-- @module fun.iter

local iter

-- Wraps a function to be used as an iterator.
-- The wrapped function becomes callable and inherits methods from `iter`.
-- @treturn fun.iterator The wrapped iterator object.
wrap = =>
  _ =
    __call: @
    __index: iter
  setmetatable _, _

--- The main iterator constructor and stepping function.
-- This is called when `fun.iter(t)` is used.
-- @tparam table t
-- @tparam[opt=1] integer step
-- @tparam[opt] integer i
-- @treturn fun.iterator
iter =
  __call: (t, step=1, i=(step > 0 and step or #t)) =>
    i -= step
    wrap ->
      i += step
      t[i]

  --- Returns the first element that satisfies the predicate `fn`.
  -- @tparam function fn
  -- @treturn any|nil
  any: (fn) => @getn 1, fn

  --- Calls `fn` for each element in the iterator.
  -- @tparam function fn
  -- @treturn fun.iterator self (to allow chaining, though `each` is usually terminal).
  each: (fn) =>
    while true
      if v = @!
        fn v
      else break
    @ -- Return self to allow chaining, though `each` is usually a terminal operation.

  -- @tparam integer n
  -- @tparam function fn
  -- @treturn any|nil The nth item matching fn, or nil.
  getn: (n, fn) =>
    i = 1
    while true
      if v = @!
        if fn v
          return v if i == n
          i += 1
      else break

  --- Creates a new iterator that applies `fn` to each element of the current iterator.
  -- @tparam function fn
  -- @treturn fun.iterator
  map: (fn) =>
    wrap ->
      if v = @!
        fn v

  --- Creates a new iterator that applies `fn` to each element and its 1-based index.
  -- @tparam function fn
  -- @treturn fun.iterator
  imap: (fn) =>
    i = 0
    wrap ->
      if v = @!
        i += 1
        fn v, i

  --- Creates a new iterator that yields only elements for which `fn` returns true.
  -- @tparam function fn
  -- @treturn fun.iterator
  filter: (fn) =>
    wrap ->
      while true
        if v = @!
          if fn v
            return v
        else return nil

  --- Creates a new iterator that yields at most `n` elements from the current iterator.
  -- @tparam integer n
  -- @treturn fun.iterator
  take: (n) =>
    i = 0
    wrap ->
      i += 1
      @! if i <= n

  --- Collects all elements from the iterator into a new array.
  -- @treturn table An array (list-like table) containing all elements from the iterator.
  toarray: =>
    t = {}
    while true
      if v = @!
        t[#t+1] = v
      else break
    t

  --- Reduces the iterator's elements to a single value using a binary function.
  -- @tparam function fn
  -- @tparam[opt] any initial
  -- @treturn any
  -- @usage
  -- local sum = fun.iter({1,2,3,4})\reduce (acc, val) -> acc + val
  -- local product = fun.iter({1,2,3,4})\reduce (((acc, val) -> acc * val), 1)
  reduce: (fn, initial) =>
    accum = initial or @!
    for v in @
      accum = fn accum, v
    accum

iter.__index = iter
setmetatable iter, iter

--- Creates an iterator from a generator function.
-- The generator function `fn` is called repeatedly without arguments to produce values.
-- @tparam function fn
-- @treturn fun.iterator
-- @usage
-- local i = 0
-- local count_up = fun.generate -> i += 1; return i <= 5 and i or nil
-- for val in count_up do print(val) end -- prints 1, 2, 3, 4, 5
generate = (fn) -> wrap -> fn!

--- Creates an iterator that generates numbers in a range. MoonScript's implicit `self` means:
-- `fun.range(max)` -> `self` is `max`, `max_param` is `nil`. Generates 1 to `max`.
-- `fun.range(start, max)` -> `self` is `start`, `max_param` is `max`. Generates `start` to `max`.
-- `fun.range(start, max, step)` -> `self` is `start`, `max_param` is `max`, `step_param` is `step`.
-- If only one argument `max` is given, it generates from `1` to `max` with a step of `1`.
-- If `self` is a number and `max` is provided, it generates from `self` to `max`.
-- If `self` is a number and `max` is not provided, it generates from `1` to `self`.

-- @tparam[opt] number max_param
-- @tparam[opt=1] number step_param
-- @treturn fun.iterator
-- @usage
-- for i in fun.range(5) do print(i) end -- 1, 2, 3, 4, 5
-- for i in fun.range(1, 5, 2) do print(i) end -- 1, 3, 5
-- -- Using the colon syntax (equivalent to fun.range(t, max, step))
-- for i in (1)\range(5, 2) do print(i) end -- 1, 3, 5
range = (max, step) =>
  step or= 1
  i = max and @-step or 0
  max or= @
  wrap ->
    i += step
    i if i <= max

{:iter, :wrap, :generate, :range}
