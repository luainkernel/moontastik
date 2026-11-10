--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/lib/test_sha.moon
-- Tests for the hand-written ipparse/lib/sha.lua (SHA-256 + HMAC-SHA256).
-- sha.lua requires Lua 5.3+ native bitwise operators; skip on LuaJIT/5.1.

util = require "ipparse.lib.util"
{:test, :summary} = util

ok, sha = pcall require, "ipparse.lib.sha"
unless ok and sha and sha.sha256 and sha.hmac
  test "sha: unavailable on this runtime (skipped)", -> true
  summary "sha"
  return

{:sha256, :hmac, :bin_to_hex} = sha

hex = (s) -> bin_to_hex s

-- FIPS 180-2 / NIST short message vectors.
test "sha: FIPS 180-2 'abc'", ->
  assert hex(sha256 "abc") ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

test "sha: FIPS 180-2 empty message", ->
  assert hex(sha256 "") ==
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

test "sha: FIPS 180-2 64 x 'a'", ->
  assert hex(sha256 (string.rep "a", 64)) ==
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"

test "sha: NIST 100 x 'a'", ->
  assert hex(sha256 (string.rep "a", 100)) ==
    "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"

test "sha: NIST long message", ->
  assert hex(sha256 string.rep "a", 1000) ==
    "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"

-- HMAC-SHA256 (RFC 4231).
test "hmac: RFC 4231 test case 1", ->
  key = string.rep "\x0b", 20
  digest = hmac sha256, key, "Hi There"
  assert #digest == 32, "hmac must return a 32-byte binary digest"
  assert hex(digest) ==
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

test "hmac: RFC 4231 test case 2", ->
  digest = hmac sha256, "Jefe", "what do ya want for nothing?"
  assert hex(digest) ==
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

summary "sha"
