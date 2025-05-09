--- Small library for basic functional programming primitives.
-- Provides utilities for memoization, iteration, and other functional constructs.
-- @module fun

:sort = table
unpack or= table.unpack

--- Creates a memoized version of a single-argument function.
-- The cache uses the input argument as the key.
-- If the argument is `nil` or not provided, the original function is called directly without caching.
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
    -- If x is nil, we can't use it as a table key reliably for caching.
    -- The original code's `if not x` would also trigger for `false`.
    -- Let's assume the intent was to bypass cache for nil.
    return @(x) if not x
    r = tmp[x] or {@ x}
    tmp[x] = r if x
    unpack r

--- Creates a memoized version of a multi-argument function.
-- The cache is hierarchical, using arguments as keys at successive levels.
-- `nil` arguments are handled by using a special internal `_nil` placeholder.
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

bidirmt_gen = ->
  _mem = setmetatable {}, __mode: "kv"
  (val) =>
    if _k = _mem[val]
      return _k
    for k, v in pairs @
      if v == val
        _mem[val] = k
        return k


--- Modifies a table in-place to create a bidirectional mapping.
-- For each key-value pair `(k, v)`, it adds `(v, k)`.
-- Assumes values are unique and hashable to be used as keys.
-- @treturn table self
-- @usage
-- local t = {a = 1, b = 2}
-- fun.bidirectional(t) -- t is now {a = 1, b = 2, [1] = "a", [2] = "b"}
bidirectional = => setmetatable @, __index: bidirmt_gen!

--- Modifies an array-like table in-place to make it zero-indexed.
-- It copies `@[i+1]` to `@[i]` for `i` from `0` to `#@-1`.
-- The original 1-indexed elements are preserved.
-- @treturn table self
-- @usage
-- local arr = {"a", "b", "c"} -- arr[1]="a", arr[2]="b", arr[3]="c"
-- fun.zero_indexed(arr) -- arr[0]="a", arr[1]="b", arr[2]="c" (original elements still there)
zero_indexed = =>
  @[i] = @[i+1] for i = 0, #@
  @

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

--- Returns an iterator over the key-value pairs of a table, sorted by keys.

-- @tparam[opt] function f
-- Defaults to a function that compares types first, then values (numbers numerically, others as strings).
-- @treturn function iterator `() -> any|nil key, any|nil value`
-- @usage for k, v in fun.opairs(my_table) do print(k, v) end
opairs = (f=(a,b) -> if type(a) == type(b) then a < b else "#{a}" < "#{b}") =>
  keys, i = {}, 1
  for k in pairs @
    keys[i] = k
    i += 1
  sort keys, f
  i = 0
  ->
    i += 1
    keys[i], @[keys[i]]

--- Wraps a function call in `xpcall` to catch errors.
-- If an error occurs, it prints the error and a traceback, then calls an optional `op` function.
-- @tparam function fn
-- @tparam[opt] function op
-- @treturn function A new, protected function.
-- @usage
-- -- The returned protected function takes:
-- -- @tparam ...any ... Arguments for the original `fn`.
-- -- @treturn ...any|nil Results from `fn` or `op` (see main description for conditions).
protected = (fn, op) -> (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ->
  ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall (
    -> fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
  ), (err) ->
    print err
    print debug.traceback!
    op! if op
  if ok
    a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z


--- The main export table for the `fun` module.
-- It provides direct access to functions like `memo`, `range`, etc.
-- Additionally, it has a special `__index` metamethod that allows
-- `iter` methods (like `map`, `filter`, `reduce`) to be called directly
-- on the `fun` module itself if the first argument is a table (or something `iter` can wrap).
-- This provides a convenient shortcut.
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
  :bidirectional, :memo, :memoN, :iter, :wrap, :range, :opairs, :generate, :zero_indexed, :protected
  __index: (_, k) ->
    fn = (...) =>
      o = (type(@) == 'table' and iter or wrap) @
      o[k] o, ...
    _[k] = fn
    fn
}

setmetatable _, _
