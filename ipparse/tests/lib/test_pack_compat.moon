--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_pack_compat.moon
-- Byte-for-byte equivalence tests for the LuaJIT pack fallback.

util = require "ipparse.lib.util"
{:test} = util
pack_compat = require "ipparse.lib.pack_compat"
pack = pack_compat.pack or string.pack
-- Native string.pack rejects the two fallback-only behaviours tested below.
is_fallback = pack != string.pack

from_hex = (h) ->
  out = h\gsub "..", (cc) -> string.char tonumber cc, 16
  out
tunpack = unpack or table.unpack

-- Big-endian header-like mix of 16-bit and 8-bit fields.
test "pack_compat: >H B B H H H H", ->
  got = pack ">H B B H H H H", 1, 2, 3, 4, 5, 6, 7
  expected = from_hex "000102030004000500060007"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Big-endian mix with a 4-byte integer and a 2-byte-prefixed string.
test "pack_compat: >H H I4 s2", ->
  got = pack ">H H I4 s2", 1, 1, 300, "abcd"
  expected = from_hex "000100010000012c000461626364"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Little-endian 4-byte integer.
test "pack_compat: <I4", ->
  got = pack "<I4", 0x01020304
  expected = from_hex "04030201"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Signed 16-bit negative value wraps to two's complement.
test "pack_compat: >i2 negative", ->
  got = pack ">i2", -2
  expected = from_hex "fffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Fixed-width string shorter than the field is NUL-padded.
test "pack_compat: >c4 short", ->
  got = pack ">c4", "ab"
  expected = from_hex "61620000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

if is_fallback
  -- Fixed-width string longer than the field is truncated.
  test "pack_compat: >c4 long", ->
    got = pack ">c4", "abcdef"
    expected = from_hex "61626364"
    assert got == expected, "got: #{got}\nexp: #{expected}"

-- c in last position after integer writes: whole packet in one buffer write.
test "pack_compat: >H c4 ends with a buffer write", ->
  got = pack ">H c4", 0x0102, "ab"
  expected = from_hex "010261620000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- c AFTER an emitting option (s2): the emitted part must stay first.
test "pack_compat: >H s2 c4 mixes emit and buffer write", ->
  got = pack ">H s2 c4", 1, "xy", "ab"
  expected = from_hex "00010002787961620000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 64 bytes and below are copied into the buffer, above that they keep the
-- emitting path: both must produce the very same bytes.
test "pack_compat: c64/c65/c80 identical full and padded", ->
  for sz in *{1, 2, 63, 64, 65, 80}
    full = string.rep "A", sz
    got = pack ">c#{sz}", full
    assert got == full, "c#{sz} full input: got #{#got} bytes, expected #{sz}"
    pad = pack ">c#{sz}", "A"
    assert pad == "A" .. string.rep("\0", sz - 1),
      "c#{sz} padded: got #{#pad} bytes, expected #{sz}"

-- NUL-terminated string gets a trailing \0.
test "pack_compat: z", ->
  got = pack "z", "hello"
  expected = from_hex "68656c6c6f00"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Padding emits one NUL byte.
test "pack_compat: x", ->
  got = pack "x"
  expected = from_hex "00"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 3-byte big-endian unsigned integer.
test "pack_compat: >I3", ->
  got = pack ">I3", 0x010203
  expected = from_hex "010203"
  assert got == expected, "got: #{got}\nexp: #{expected}"

if is_fallback
  -- uint8 keeps the low byte of out-of-range values (300 % 256 == 44).
  test "pack_compat: B 300 wraps", ->
    got = pack "B", 300
    expected = from_hex "2c"
    assert got == expected, "got: #{got}\nexp: #{expected}"

-- More than eight arguments used to exercise the generic vararg path; with
-- the shared 16-slot array they now fill it instead (9 to 16 values).
test "pack_compat: >B x10 more than 8 args", ->
  got = pack ">B B B B B B B B B B", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
  expected = from_hex "0102030405060708090a"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Exactly sixteen arguments: last value fitting in the shared array.
test "pack_compat: 16 args fill the shared array", ->
  got = pack ">B B B B B B B B B B B B B B B B",
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
  expected = from_hex "0102030405060708090a0b0c0d0e0f10"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Seventeen arguments: one past the shared array, back to the vararg path.
test "pack_compat: more than 16 args uses the vararg path", ->
  fmt = ">B " .. string.rep("B ", 16)
  got = pack fmt,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
  expected = from_hex "0102030405060708090a0b0c0d0e0f1011"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Padding byte between integers.
test "pack_compat: >H x H", ->
  got = pack ">H x H", 1, 2
  expected = from_hex "0001000002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- String options in the middle of integer fields.
test "pack_compat: >H c2 H", ->
  got = pack ">H c2 H", 1, "ab", 2
  expected = from_hex "000161620002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >H z H", ->
  got = pack ">H z H", 1, "ab", 2
  expected = from_hex "00016162000002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >H s2 H", ->
  got = pack ">H s2 H", 1, "ab", 2
  expected = from_hex "0001000261620002"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Signed 32-bit negative value wraps to two's complement.
test "pack_compat: >i4 negative", ->
  got = pack ">i4", -2
  expected = from_hex "fffffffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- 64-bit little-endian value above the 32-bit range keeps its high word.
test "pack_compat: <I8 above 32-bit range", ->
  got = pack "<I8", 0x100000000
  expected = from_hex "0000000001000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- Empty format yields an empty string.
test "pack_compat: empty format", ->
  got = pack ""
  assert got == "", "got: #{got}"

-- ─── 64-bit signed and unsigned values ──────────────────────────────────────

unpack = pack_compat.unpack or string.unpack

-- -2 as a signed 64-bit value is 0xff..fe in two's complement.
test "pack_compat: >i8 negative bytes", ->
  got = pack ">i8", -2
  expected = from_hex "fffffffffffffffe"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- -1 as a signed 64-bit value is all ones in two's complement.
test "pack_compat: <i8 negative one bytes", ->
  got = pack "<i8", -1
  expected = from_hex "ffffffffffffffff"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- -(2^53), exactly representable as a double, keeps its low 64-bit pattern.
test "pack_compat: >i8 negative 2^53 bytes", ->
  got = pack ">i8", -9007199254740992
  expected = from_hex "ffe0000000000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: <I8 above 32-bit range bytes", ->
  got = pack "<I8", 0x100000000
  expected = from_hex "0000000001000000"
  assert got == expected, "got: #{got}\nexp: #{expected}"

-- "=" selects the native byte order: little-endian on the x86/ARM hosts used
-- by the test suite (and the documented assumption of the pure-Lua fallback).
test "pack_compat: =I4 native little-endian", ->
  got = pack "=I4", 0x01020304
  expected = from_hex "04030201"
  assert got == expected, "got: #{got}\nexp: #{expected}"

test "pack_compat: >i8 negative round-trip", ->
  v, pos = unpack ">i8", pack(">i8", -2)
  assert v == -2, "got: #{v}"
  assert pos == 9, "pos: #{pos}"

-- ─── Truncated input must raise, as native string.unpack does ───────────────

test "pack_compat: unpack B on empty string raises", ->
  ok, err = pcall unpack, "B", "", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack c8 on 3-byte string raises", ->
  ok, err = pcall unpack, "c8", "abc", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack >s1 with truncated body raises", ->
  ok, err = pcall unpack, ">s1", "\005ab", 1
  assert not ok and tostring(err)\match("too short"),
    "expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack full-width controls still work", ->
  assert unpack("B", "a", 1) == 97, "B on 'a'"
  assert unpack("c3", "abc", 1) == "abc", "c3 on 'abc'"
  assert unpack(">s1", "\002ab", 1) == "ab", "s1 on '\\002ab'"
  assert unpack("c0", "", 1) == "", "c0 on ''"
-- Round-trips migrated from the old out-of-tree tests/pack.moon.
test "pack_compat: B round-trip", ->
  packed = pack "B", 35
  result, pos = unpack "B", packed
  assert result == 35, "got: #{result}"
  assert pos == 2, "pos: #{pos}"

test "pack_compat: I round-trip", ->
  packed = pack "I", 35
  result, pos = unpack "I", packed
  assert result == 35, "got: #{result}"
  assert pos == 5, "pos: #{pos}"

test "pack_compat: s2 round-trip", ->
  packed = pack "s2", "he"
  result, pos = unpack "s2", packed
  assert result == "he", "got: #{result}"
  assert pos == 2 * #result + 1, "pos: #{pos}"

-- ─── Every option: endianness, widths and round-trips ──────────────────────

-- int8 / uint8 both directions.
test "pack_compat: b/B endianness and unpack", ->
  assert pack(">b", -1) == from_hex "ff", ">b -1"
  assert pack("<b", -1) == from_hex "ff", "<b -1"
  assert pack(">B", 255) == from_hex "ff", ">B 255"
  assert pack("<B", 255) == from_hex "ff", "<B 255"
  v, pos = unpack ">b", from_hex "fe"
  assert v == -2 and pos == 2, "unpack >b -2 (got #{v}, #{pos})"
  v, pos = unpack "<B", from_hex "fe"
  assert v == 254 and pos == 2, "unpack <B 254 (got #{v}, #{pos})"

-- int16 / uint16 both directions.
test "pack_compat: h/H endianness and unpack", ->
  assert pack(">h", -2) == from_hex "fffe", ">h -2"
  assert pack("<h", -2) == from_hex "feff", "<h -2"
  assert pack(">H", 513) == from_hex "0201", ">H 513"
  assert pack("<H", 513) == from_hex "0102", "<H 513"
  v, pos = unpack ">h", from_hex "fffe"
  assert v == -2 and pos == 3, "unpack >h -2 (got #{v}, #{pos})"
  v, pos = unpack "<H", from_hex "0102"
  assert v == 513 and pos == 3, "unpack <H 513 (got #{v}, #{pos})"

-- 3-byte unsigned, both byte orders.
test "pack_compat: I3 endianness and unpack", ->
  assert pack(">I3", 0x010203) == from_hex "010203", ">I3"
  assert pack("<I3", 0x010203) == from_hex "030201", "<I3"
  v, pos = unpack "<I3", from_hex "030201"
  assert v == 0x010203 and pos == 4, "unpack <I3 (got #{v}, #{pos})"

-- 5- and 6-byte integers exercise the small-loop writer.
test "pack_compat: I5/I6 bytes", ->
  assert pack(">I5", 0x0102030405) == from_hex "0102030405", ">I5"
  assert pack("<I5", 0x0102030405) == from_hex "0504030201", "<I5"
  assert pack(">I6", 0x010203040506) == from_hex "010203040506", ">I6"
  assert pack("<I6", 0x010203040506) == from_hex "060504030201", "<I6"
  v, pos = unpack ">I5", from_hex "0102030405"
  assert v == 0x0102030405 and pos == 6, "unpack >I5 (got #{v}, #{pos})"
  v, pos = unpack "<I6", from_hex "060504030201"
  assert v == 0x010203040506 and pos == 7, "unpack <I6 (got #{v}, #{pos})"

-- 7- and 8-byte integers keep their high bytes (values kept below 2^53).
test "pack_compat: I7/I8 bytes and unpack", ->
  assert pack(">I7", 0x01020304050607) == from_hex "01020304050607", ">I7"
  assert pack("<I7", 0x01020304050607) == from_hex "07060504030201", "<I7"
  assert pack(">I8", 0x0123456789abcd) == from_hex "000123456789abcd", ">I8"
  assert pack("<I8", 0x0123456789abcd) == from_hex "cdab896745230100", "<I8"
  v, pos = unpack ">I7", from_hex "01020304050607"
  assert v == 0x01020304050607 and pos == 8, "unpack >I7 (got #{v}, #{pos})"
  v, pos = unpack "<I8", from_hex "cdab896745230100"
  assert v == 0x0123456789abcd and pos == 9, "unpack <I8 (got #{v}, #{pos})"

-- Signed limits for 1- to 4-byte fields round-trip exactly.
test "pack_compat: signed i1..i4 limits", ->
  sizes = {
    {1, -128, 127}
    {2, -32768, 32767}
    {3, -8388608, 8388607}
    {4, -2147483648, 2147483647}
  }
  for item in *sizes
    sz, mn, mx = item[1], item[2], item[3]
    fmt = ">" .. "i" .. sz
    for v in *{mn, mx, -1, 0}
      got = pack fmt, v
      assert #got == sz, "#{fmt}: width #{#got} != #{sz}"
      r, pos = unpack fmt, got
      assert r == v, "#{fmt} round-trip: #{r} != #{v}"
      assert pos == sz + 1, "#{fmt} pos: #{pos}"

-- Unsigned limits for 1- to 4-byte fields round-trip exactly.
test "pack_compat: unsigned I1..I4 limits", ->
  sizes = {
    {1, 255}
    {2, 65535}
    {3, 16777215}
    {4, 4294967295}
  }
  for item in *sizes
    sz, mx = item[1], item[2]
    fmt = ">" .. "I" .. sz
    for v in *{0, 1, mx}
      got = pack fmt, v
      assert #got == sz, "#{fmt}: width #{#got} != #{sz}"
      r, pos = unpack fmt, got
      assert r == v, "#{fmt} round-trip: #{r} != #{v}"
      assert pos == sz + 1, "#{fmt} pos: #{pos}"

-- 64-bit option letters l/L/j/J/T: same bytes as i8/I8, signed or not.
test "pack_compat: l/L/j/J/T bytes and unpack", ->
  for fmt in *{"l", "j"}
    got = pack ">" .. fmt, -1
    expected = from_hex "ffffffffffffffff"
    assert got == expected, ">#{fmt} -1"
    v, pos = unpack ">" .. fmt, got
    assert v == -1 and pos == 9, "unpack >#{fmt} -1 (got #{v}, #{pos})"
  for fmt in *{"L", "J", "T"}
    got = pack ">" .. fmt, 1
    expected = from_hex "0000000000000001"
    assert got == expected, ">#{fmt} 1"
    v, pos = unpack ">" .. fmt, got
    assert v == 1 and pos == 9, "unpack >#{fmt} 1 (got #{v}, #{pos})"
  assert pack("<L", 1) == from_hex "0100000000000000", "<L 1"

-- s[n] with explicit sizes, both byte orders.
test "pack_compat: s1/s2/s4/s8 round-trip", ->
  for sz in *{1, 2, 4, 8}
    for prefix in *{">", "<"}
      fmt = prefix .. "s" .. sz
      got = pack fmt, "ab"
      r, pos = unpack fmt, got
      assert r == "ab", "#{fmt} round-trip: #{r}"
      assert pos == sz + 3, "#{fmt} pos: #{pos}"
  assert pack(">s1", "ab") == from_hex "026162", ">s1"
  assert pack("<s4", "ab") == from_hex "020000006162", "<s4"
  assert pack("s", "ab") == from_hex "02000000000000006162", "s default width and native order"

-- c[n] explicit and default widths.
test "pack_compat: c1/c2/c0 and unpack", ->
  assert pack("c1", "a") == "a", "c1"
  assert pack("c2", "a") == from_hex "6100", "c2 pads"
  v, pos = unpack "c2", "abc"
  assert v == "ab" and pos == 3, "unpack c2 (got #{v}, #{pos})"
  v, pos = unpack "c0", "abc"
  assert v == "" and pos == 1, "unpack c0 (got '#{v}', #{pos})"

-- z in the middle and at the end, with unpack.
test "pack_compat: z round-trip and position", ->
  assert pack("z", "") == from_hex "00", "z empty"
  v, pos = unpack "z", "hello\0"
  assert v == "hello" and pos == 7, "unpack z (got #{v}, #{pos})"
  got = pack ">z B", "ab", 7
  assert got == from_hex "61620007", ">z B"
  a, b, pos = unpack ">z B", got
  assert a == "ab" and b == 7 and pos == 5, "unpack >z B (got #{a}, #{b}, #{pos})"

-- x pads one byte; unpack skips it and reports the next position.
test "pack_compat: x unpack skips one byte", ->
  assert pack("x") == from_hex "00", "x emits one NUL"
  pos = unpack "x", "\0"
  assert pos == 2, "unpack x pos: #{pos}"
  b, pos = unpack "x B", "\0\7"
  assert b == 7 and pos == 3, "unpack x B (got #{b}, #{pos})"

-- Endianness modifiers: "<", ">", "=" and "!n" alignment.
test "pack_compat: endianness modifiers and alignment", ->
  assert pack(">H", 1) == from_hex "0001", ">"
  assert pack("<H", 1) == from_hex "0100", "<"
  assert pack("=H", 1) == pack("<H", 1), "= follows native order"
  assert pack(">!4H", 1) == from_hex "0001", "!4 alignment"
  assert pack("! H", 1) == pack("<H", 1), "! without width"

-- Spaces are ignored anywhere between options.
test "pack_compat: spaces in format", ->
  got = pack " > H  B ", 1, 2
  assert got == from_hex "000102", "spaces in format (got #{got})"
  v, pos = unpack " > H  B ", got
  assert v == 1 and pos == 2, "unpack spaces (got #{v}, #{pos})"

-- ─── packsize ───────────────────────────────────────────────────────────────

packsize = pack_compat.packsize or string.packsize

test "pack_compat: packsize fixed formats", ->
  assert packsize("") == 0, "empty format"
  assert packsize(">H B B H") == 6, ">H B B H"
  assert packsize("i") == 4, "i default"
  assert packsize("i3") == 3, "i3"
  assert packsize("I5") == 5, "I5"
  assert packsize("c10") == 10, "c10"
  assert packsize("x") == 1, "x"
  assert packsize(">H x H") == 5, ">H x H"
  assert packsize("l") == 8, "l"
  assert packsize("j") == 8, "j"
  assert packsize("T") == 8, "T"
  assert packsize(">!4H") == 2, ">!4H"

test "pack_compat: packsize rejects variable-size formats", ->
  for opt in *{"s", "z", "s2", ">H z"}
    ok = pcall packsize, opt
    assert not ok, "packsize('#{opt}') should raise"

-- ─── Truncated input for every integer/string option ───────────────────────

test "pack_compat: unpack short data raises for every option", ->
  cases = {
    {"b", ""}
    {"B", ""}
    {"h", "\0"}
    {"H", "\0"}
    {"i2", "\0"}
    {"I2", "\0"}
    {"i8", "\0\0\0"}
    {"l", "\0\0"}
    {"L", "\0\0"}
    {"j", "\1"}
    {"J", "\1"}
    {"T", "\1"}
    {"s1", ""}
    {"s1", "\5ab"}
    {"c2", "a"}
    {"x", ""}
  }
  for item in *cases
    fmt, s = item[1], item[2]
    ok, err = pcall unpack, fmt, s, 1
    assert not ok, "unpack('#{fmt}') on short data should raise"
    assert (tostring(err)\match "too short"),
      "unpack('#{fmt}'): expected 'data string too short', got: #{tostring err}"

test "pack_compat: unpack z without terminator raises", ->
  ok, err = pcall unpack, "z", "abc", 1
  assert not ok, "unpack('z') without NUL should raise"
  assert (tostring(err)\match "z"), "error should mention z, got: #{tostring err}"

-- ─── Large buffers, injection ──────────────────────────────────────────────

-- More than 4096 bytes written to the shared buffer exercise the chunked
-- string.char path in buf_string.
if is_fallback
  -- Chunked buf_string only exists in the fallback; native string.pack is used in the kernel.
  test "pack_compat: pack writes more than 4096 bytes", ->
    fmt = string.rep ">I8 ", 600
    values = {}
    for i = 1, 600
      values[i] = 1
    got = pack fmt, tunpack values
    assert #got == 4800, "expected 4800 bytes, got #{#got}"
    assert got\sub(1, 8) == from_hex "0000000000000001", "first value corrupted"
    assert got\sub(4793, 4800) == from_hex "0000000000000001", "last value corrupted"

if is_fallback
  -- inject installs the fallback functions into the global string table.
  test "pack_compat: inject sets string.pack/unpack/packsize", ->
    saved_pack = string.pack
    saved_unpack = string.unpack
    saved_packsize = string.packsize
    ok, err = pcall ->
      pack_compat.inject!
      assert string.pack == pack_compat.pack, "string.pack not injected"
      assert string.unpack == pack_compat.unpack, "string.unpack not injected"
      assert string.packsize == pack_compat.packsize, "string.packsize not injected"
      assert string.pack("B", 7) == from_hex "07", "injected pack wrong"
    string.pack = saved_pack
    string.unpack = saved_unpack
    string.packsize = saved_packsize
    assert ok, err

util.summary "pack_compat"
