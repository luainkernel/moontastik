--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

util = require"ipparse.lib.util"
{:test} = util
{:bidirectional, :memo, :memoN, :iter, :range, :opairs, :zero_indexed} = require"ipparse.fun"
fun = require"ipparse.fun"

test "bidirectional forward lookup", ->
  t = bidirectional {a: 1, b: 2}
  assert t.a == 1, "t.a should be 1"
  assert t.b == 2, "t.b should be 2"

test "bidirectional reverse lookup", ->
  t = bidirectional {a: 1, b: 2}
  assert t[1] == "a", "t[1] should be 'a', got '#{t[1]}'"
  assert t[2] == "b", "t[2] should be 'b', got '#{t[2]}'"

test "memo caches single-arg function", ->
  count = 0
  fn = memo (x) ->
    count += 1
    x * 2
  assert fn(5) == 10, "first call should return 10"
  assert fn(5) == 10, "second call should still return 10"
  assert count == 1, "original called #{count} times, expected 1"

test "memoN caches multi-arg function", ->
  count = 0
  fn = memoN (a, b) ->
    count += 1
    a + b
  assert fn(3, 4) == 7, "first call should return 7"
  assert fn(3, 4) == 7, "second call should still return 7"
  assert count == 1, "memoN: original called #{count} times, expected 1"

test "iter toarray basic", ->
  arr = iter({10, 20, 30})\toarray!
  assert #arr == 3, "expected 3 elements, got #{#arr}"
  assert arr[1] == 10, "arr[1] should be 10"
  assert arr[2] == 20, "arr[2] should be 20"
  assert arr[3] == 30, "arr[3] should be 30"

test "iter map doubles values", ->
  arr = iter({1, 2, 3})\map((x) -> x*2)\toarray!
  assert arr[1] == 2, "arr[1] should be 2"
  assert arr[2] == 4, "arr[2] should be 4"
  assert arr[3] == 6, "arr[3] should be 6"

test "iter filter keeps evens", ->
  arr = iter({1, 2, 3, 4, 5})\filter((x) -> x%2==0)\toarray!
  assert #arr == 2, "expected 2 elements, got #{#arr}"
  assert arr[1] == 2, "arr[1] should be 2"
  assert arr[2] == 4, "arr[2] should be 4"

test "iter reduce sums values", ->
  sum = iter({1, 2, 3, 4, 5})\reduce (acc, v) -> acc + v
  assert sum == 15, "sum should be 15, got #{sum}"

test "iter take first N", ->
  arr = iter({1, 2, 3, 4, 5})\take(3)\toarray!
  assert #arr == 3, "expected 3 elements, got #{#arr}"
  assert arr[1] == 1, "arr[1] should be 1"
  assert arr[3] == 3, "arr[3] should be 3"

test "range generates 1..5", ->
  arr = {}
  for i in range(5)
    arr[#arr+1] = i
  assert #arr == 5, "expected 5 elements, got #{#arr}"
  assert arr[1] == 1, "arr[1] should be 1"
  assert arr[5] == 5, "arr[5] should be 5"

test "range with start and end", ->
  arr = {}
  for i in range(2, 5)
    arr[#arr+1] = i
  assert arr[1] == 2, "arr[1] should be 2"
  assert arr[4] == 5, "arr[4] should be 5"

test "opairs returns sorted keys", ->
  t = {c: 3, a: 1, b: 2}
  keys = {}
  for k, v in opairs(t)
    keys[#keys+1] = k
  assert keys[1] == "a", "keys[1] should be 'a', got '#{keys[1]}'"
  assert keys[2] == "b", "keys[2] should be 'b'"
  assert keys[3] == "c", "keys[3] should be 'c'"

test "zero_indexed copies t[1] to t[0]", ->
  t = zero_indexed {"x", "y", "z"}
  assert t[0] == "x", "t[0] should be 'x', got '#{t[0]}'"

test "bidirectional invalidates stale cache on key modification", ->
  t = bidirectional {a: 1}
  assert t[1] == "a", "t[1] should be 'a', got '#{t[1]}'"
  t.a = 2
  assert t[1] == nil, "t[1] should be nil after t.a changed, got '#{t[1]}'"
  assert t[2] == "a", "t[2] should be 'a' after change, got '#{t[2]}'"

test "bidirectional drops cache for deleted key", ->
  t = bidirectional {a: 1}
  assert t[1] == "a", "t[1] should be 'a', got '#{t[1]}'"
  t.a = nil
  assert t[1] == nil, "t[1] should be nil after key deletion, got '#{t[1]}'"

test "bidirectional cache cycle after deletion", ->
  t = bidirectional {x: "y", y: "x"}
  assert t["y"] == "x", "t['y'] should be 'x', got '#{t['y']}'"
  assert t["x"] == "y", "t['x'] should be 'y', got '#{t['x']}'"
  t.x = nil
  t.y = nil
  assert t["y"] == nil, "t['y'] should be nil after deletion, got '#{t['y']}'"

test "bidirectional non-regression forward and reverse lookup", ->
  t = bidirectional {a: 1, b: 2}
  assert t.a == 1, "t.a should be 1"
  assert t.b == 2, "t.b should be 2"
  assert t[1] == "a", "t[1] should be 'a'"
  assert t[2] == "b", "t[2] should be 'b'"

test "bidirectional reverse sees key added later", ->
  t = bidirectional {a: 1}
  t.b = 2
  assert t[2] == "b", "t[2] should be 'b' after adding t.b, got '#{t[2]}'"

test "bidirectional pairs only sees real entries", ->
  t = bidirectional {a: 1, b: 2}
  t[1]
  t[2]
  n = 0
  for k, v in pairs t
    n += 1
  assert n == 2, "pairs should see 2 entries, got #{n}"

test "protected only prints a traceback when leak_debug is set", ->
  original_print = _G.print
  calls = 0
  _G.print = (...) -> calls += 1
  ok, err = pcall ->
    assert rawget(fun, "leak_debug") == nil, "leak_debug should be unset"
    p = fun.protected -> 1, 2
    a, b = p!
    assert a == 1 and b == 2, "protected should return fn values"
    assert calls == 0, "expected no print call, got #{calls}"
    p = fun.protected -> error "boom"
    r = p!
    assert r == nil, "protected should return nil on error"
    assert calls == 1, "expected 1 print call, got #{calls}"
    calls = 0
    fun.leak_debug = true
    p = fun.protected -> error "boom"
    r = p!
    assert r == nil, "protected should return nil on error"
    assert calls == 2, "expected 2 print calls, got #{calls}"
    fun.leak_debug = nil
  _G.print = original_print
  assert ok, err

test "zero_indexed shifts every element down by one index", ->
  arr = {"a", "b", "c"}
  zero_indexed arr
  assert arr[0] == "a", "arr[0] should be 'a', got '#{arr[0]}'"
  assert arr[1] == "b", "arr[1] should be 'b', got '#{arr[1]}'"
  assert arr[2] == "c", "arr[2] should be 'c', got '#{arr[2]}'"
  assert arr[3] == nil, "arr[3] should be nil, got '#{arr[3]}'"

test "protected forwards multiple arguments and returns with nil holes", ->
  p = fun.protected (a, b, c) -> c, b, a
  r1, r2, r3 = p 1, nil, 3
  assert r1 == 3, "first return should be 3, got '#{r1}'"
  assert r2 == nil, "second return should be nil, got '#{r2}'"
  assert r3 == 1, "third return should be 1, got '#{r3}'"

test "protected returns no value on error and calls op", ->
  original_print = _G.print
  _G.print = -> 0
  op_calls = 0
  p = fun.protected (-> error "boom"), (-> op_calls += 1)
  n = select "#", p!
  _G.print = original_print
  assert n == 0, "protected should return no value on error, got #{n}"
  assert op_calls == 1, "op should be called once, got #{op_calls}"

test "protected forwards 26 arguments and returns", ->
  p = fun.protected (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) -> a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
  r = {p(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26)}
  assert #r == 26, "expected 26 returns, got #{#r}"
  assert r[1] == 1, "r[1] should be 1, got '#{r[1]}'"
  assert r[26] == 26, "r[26] should be 26, got '#{r[26]}'"

test "iter with a positive step yields every other element", ->
  arr = iter({10, 20, 30, 40}, 2)\toarray!
  assert #arr == 2, "expected 2 elements, got #{#arr}"
  assert arr[1] == 20 and arr[2] == 40, "step iteration mismatch"

test "iter any returns the first match", ->
  v = iter({1, 2, 3, 4})\any (x) -> x % 2 == 0
  assert v == 2, "expected 2, got #{v}"

test "iter getn returns the nth matching element", ->
  v = iter({10, 20, 30})\getn 2, (x) -> true
  assert v == 20, "expected 20, got #{v}"

test "iter each visits every element and returns the iterator", ->
  seen = { }
  it = iter {1, 2, 3}
  r = it\each (v) -> seen[#seen + 1] = v
  assert #seen == 3, "expected 3 visited elements, got #{#seen}"
  assert seen[1] == 1 and seen[3] == 3, "visited values mismatch"
  assert r == it, "each should return the iterator"

test "iter imap exposes a one-based index", ->
  arr = iter({10, 20, 30})\imap((v, i) -> v + i)\toarray!
  assert arr[1] == 11 and arr[2] == 22 and arr[3] == 33, "imap mismatch"

test "iter reduce with an initial value", ->
  sum = iter({1, 2, 3})\reduce ((acc, v) -> acc + v), 10
  assert sum == 16, "sum should be 16, got #{sum}"

test "range with a step", ->
  arr = { }
  for i in range 1, 10, 3
    arr[#arr + 1] = i
  assert #arr == 4, "expected 4 elements, got #{#arr}"
  assert arr[1] == 1 and arr[4] == 10, "stepped range mismatch"

test "generate wraps a producer function", ->
  n = 0
  gen = fun.generate ->
    n += 1
    if n <= 3
      n
  arr = gen\toarray!
  assert #arr == 3, "expected 3 elements, got #{#arr}"
  assert arr[1] == 1 and arr[3] == 3, "generated values mismatch"

test "memo forwards nil without caching", ->
  fn = memo (x) ->
    if x == nil
      42
    else
      x * 2
  assert fn(nil) == 42, "nil should be forwarded to the original"
  assert fn(5) == 10, "non-nil should still be cached"

test "memoN handles nil arguments", ->
  count = 0
  fn = memoN (a, b) ->
    count += 1
    (a or 0) + (b or 0)
  assert fn(1, nil) == 1, "expected 1"
  assert fn(1, nil) == 1, "expected cached 1"
  assert fn(nil, nil) == 0, "expected 0 for two nils"
  assert count == 2, "original called #{count} times, expected 2"

test "opairs sorts mixed key types without error", ->
  keys = { }
  for k in opairs {[1]: "number", a: "string"}
    keys[#keys + 1] = k
  assert #keys == 2, "expected 2 keys, got #{#keys}"

test "fun.map table shortcut maps an array", ->
  arr = fun.map({1, 2, 3}, (x) -> x * 2)\toarray!
  assert #arr == 3, "expected 3 elements, got #{#arr}"
  assert arr[1] == 2 and arr[3] == 6, "table shortcut map mismatch"

test "fun.tables loads alone and exposes its functions", ->
  t = require "ipparse.fun.tables"
  assert type(t.bidirectional) == "function", "tables.bidirectional should be a function"
  assert type(t.zero_indexed) == "function", "tables.zero_indexed should be a function"
  assert type(t.opairs) == "function", "tables.opairs should be a function"

test "fun.memo loads alone and exposes its functions", ->
  m = require "ipparse.fun.memo"
  assert type(m.memo) == "function", "memo.memo should be a function"
  assert type(m.memoN) == "function", "memo.memoN should be a function"

test "fun.iter loads alone and exposes its functions", ->
  m = require "ipparse.fun.iter"
  assert type(m.iter) == "table", "iter.iter should be a table"
  assert type(m.wrap) == "function", "iter.wrap should be a function"
  assert type(m.generate) == "function", "iter.generate should be a function"
  assert type(m.range) == "function", "iter.range should be a function"

test "fun.protected loads alone and exposes protected and leak_debug", ->
  m = require "ipparse.fun.protected"
  assert type(m.protected) == "function", "protected.protected should be a function"
  assert rawget(m, "leak_debug") == nil, "protected.leak_debug should start unset"
  m.leak_debug = true
  assert m.leak_debug == true, "protected.leak_debug should be writable"
  m.leak_debug = nil

test "fun facade re-exports the same functions as the submodules", ->
  tables = require "ipparse.fun.tables"
  memo_mod = require "ipparse.fun.memo"
  iter_mod = require "ipparse.fun.iter"
  protected_mod = require "ipparse.fun.protected"
  assert fun.bidirectional == tables.bidirectional, "bidirectional identity mismatch"
  assert fun.zero_indexed == tables.zero_indexed, "zero_indexed identity mismatch"
  assert fun.opairs == tables.opairs, "opairs identity mismatch"
  assert fun.memo == memo_mod.memo, "memo identity mismatch"
  assert fun.memoN == memo_mod.memoN, "memoN identity mismatch"
  assert fun.iter == iter_mod.iter, "iter identity mismatch"
  assert fun.wrap == iter_mod.wrap, "wrap identity mismatch"
  assert fun.generate == iter_mod.generate, "generate identity mismatch"
  assert fun.range == iter_mod.range, "range identity mismatch"
  assert fun.protected == protected_mod.protected, "protected identity mismatch"

util.summary "fun"
