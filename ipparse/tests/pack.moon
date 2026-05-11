#!/usr/bin/env moon

--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--


:test = require"lib.util"
:pack, :unpack = require"lib.pack_compat"
:concat = table

test "PACK pack / unpack B", ->
  packed = pack "B", 35
  result, new_offset = unpack "B", packed
  assert result == 35
  assert new_offset == 2

test "PACK pack / unpack I", ->
  packed = pack "I", 35
  result, new_offset = unpack "I", packed
  assert result == 35
  assert new_offset == 5

test "PACK pack / unpack s2", ->
  test_str = "he"
  packed = pack "s2", test_str
  result, new_offset = unpack "s2", packed
  assert result == test_str
  assert new_offset == 2*#test_str + 1, "OFFSET: #{new_offset}, EXPECTED: #{2*#test_str + 1}"

