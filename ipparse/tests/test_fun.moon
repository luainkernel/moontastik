util = require"ipparse.lib.util"
{:test} = util
{:bidirectional, :memo, :memoN, :iter, :range, :opairs, :zero_indexed} = require"ipparse.fun"

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
util.summary "fun"
