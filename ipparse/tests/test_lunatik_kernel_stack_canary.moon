--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/test_lunatik_kernel_stack_canary.moon
-- Kernel stack-margin canary for ipparse under Lunatik.
--
-- A Lunatik kernel thread has a 16 KiB stack and `lunatik_maxccalls` lets Lua
-- use 5/8 of it before raising "C stack overflow". Loading a module costs C
-- stack: every nested `require` pushes frames and the Lua parser is recursive.
-- A big module such as `ipparse.fun`, first parsed at the bottom of a require
-- chain, has already overflowed twice in practice. This test simulates nested
-- first loads of every entry module and requires a minimum depth margin.
--
-- Run with: lunatik run ipparse/tests/test_lunatik_kernel_stack_canary

-- Number of nested requires a consumer may go through before first touching an
-- ipparse entry module; raise it as the margin grows, never lower it to make
-- the test pass.
REQUIRED_DEPTH = 2
MAX_PROBE = 12

ENTRY_MODULES = {
  "ipparse"
  "ipparse.fun"
  "ipparse.l2.ethernet"
  "ipparse.l3.ip"
  "ipparse.l3.ip4"
  "ipparse.l3.ip6"
  "ipparse.l3.fragmented_ip4"
  "ipparse.l4.tcp"
  "ipparse.l4.udp"
  "ipparse.l4.tcp_stream"
  "ipparse.l4.quic"
  "ipparse.l4.quic.frames"
  "ipparse.l7.dns"
  "ipparse.l7.tls"
  "ipparse.l7.tls.handshake"
  "ipparse.l7.quic"
  "ipparse.l7.quic.session"
  "ipparse.lib.hkdf"
  "ipparse.lib.crypto.backend.lunatik"
}

pass = 0
total = 0
id = 0

-- Drop every loaded ipparse module so each probe reparses them from scratch.
-- Collect keys first: never mutate a table while iterating over `pairs`.
unload_ipparse = ->
  keys = {}
  for k in pairs package.loaded
    if type(k) == "string" and (k == "ipparse" or k\sub(1, 8) == "ipparse.")
      keys[#keys + 1] = k
  for i = 1, #keys
    package.loaded[keys[i]] = nil

-- Loader factory: require `next_name` then report success.
make_loader = (next_name) ->
  ->
    require next_name
    true

-- Simulate a first load of `mod` from `depth` nested requires.
-- Returns pcall's ok, err; leaves no trace in package.preload/package.loaded.
probe = (mod, depth) ->
  id += 1
  names = {}
  for k = 1, depth
    names[k] = "ipparse_canary.#{id}.#{k}"
  first = mod
  if depth > 0
    first = names[1]
    for k = 1, depth
      next_name = mod
      if k < depth
        next_name = names[k + 1]
      package.preload[names[k]] = make_loader next_name
  unload_ipparse!
  ok, err = pcall require, first
  for k = 1, depth
    package.preload[names[k]] = nil
    package.loaded[names[k]] = nil
  unload_ipparse!
  ok, err

is_stack_error = (err) ->
  s = tostring err
  return true if s\find "stack overflow", 1, true
  return true if s\find "error in error handling", 1, true
  false

min_max = nil

for i = 1, #ENTRY_MODULES
  mod = ENTRY_MODULES[i]
  max_depth = 0
  skipped = false
  skip_err = nil
  ok0, err0 = probe mod, 0
  if not ok0
    if is_stack_error err0
      max_depth = 0
    else
      skipped = true
      skip_err = err0
  if not skipped
    for d = 1, MAX_PROBE
      ok, _err = probe mod, d
      if ok
        max_depth = d
      else
        break

  total += 1
  if max_depth >= MAX_PROBE
    print "CANARY\t#{mod}\tmax_depth>=#{MAX_PROBE}"
  else
    print "CANARY\t#{mod}\tmax_depth=#{max_depth}"
  if skipped
    print "SKIP\t#{mod}\t#{skip_err}"
  else
    if max_depth >= REQUIRED_DEPTH
      pass += 1
      print "PASS\tstack canary: #{mod} loads from depth #{max_depth}"
    else
      print "FAIL\tstack canary: #{mod} loads from depth #{max_depth} only (need #{REQUIRED_DEPTH})"
    if min_max == nil or max_depth < min_max
      min_max = max_depth

if min_max == nil
  min_max = 0
print "==> Stack canary: #{pass}/#{total}, min max_depth=#{min_max}"
unload_ipparse!
