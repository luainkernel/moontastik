--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Table helpers: bidirectional mappings, zero-based arrays, sorted pairs.
-- Split out of `ipparse.fun` so protocol modules can load only these small
-- primitives without pulling in the rest of the functional library.
-- @module fun.tables

:sort = table

bidirmt_gen = ->
  _mem = setmetatable {}, __mode: "kv"
  (val) =>
    _k = _mem[val]
    -- rawget (not @[_k]) validates without re-entering __index, which would
    -- recurse on an absent key.
    return _k if _k and rawget(@, _k) == val
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
-- It copies `@[i+1]` to `@[i]` for `i` from `0` to `#@`, shifting every
-- element down by one index and clearing the last slot.
-- @treturn table self
-- @usage
-- local arr = {"a", "b", "c"} -- arr[1]="a", arr[2]="b", arr[3]="c"
-- fun.zero_indexed(arr) -- arr[0]="a", arr[1]="b", arr[2]="c", arr[3]=nil
zero_indexed = =>
  @[i] = @[i+1] for i = 0, #@
  @

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

{:bidirectional, :zero_indexed, :opairs}
