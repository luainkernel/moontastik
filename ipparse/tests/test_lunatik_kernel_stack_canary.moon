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
-- Probes run under `pcall`, which itself consumes C stack, so the measured
-- depths describe a consumer that loads under `pcall`: they are pessimistic by
-- roughly one level compared with a bare `require`.
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
  "ipparse.fun.tables"
  "ipparse.fun.memo"
  "ipparse.fun.iter"
  "ipparse.fun.protected"
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
  "ipparse.l7.tls.handshake.client_hello"
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

truncate = (err) ->
  msg = (tostring err)\gsub "%s+", " "
  msg\sub 1, 120

-- Facade and heavy submodules: protocol modules never load them, so they are
-- exempt from both base-first guards (`ipparse` first, no heavy `fun`).
HEAVY_FUN = { "ipparse.fun", "ipparse.fun.iter", "ipparse.fun.memo", "ipparse.fun.protected" }
BASE_EXEMPT = {
  ["ipparse"]: true
  ["ipparse.fun"]: true
  ["ipparse.fun.tables"]: true
  ["ipparse.fun.memo"]: true
  ["ipparse.fun.iter"]: true
  ["ipparse.fun.protected"]: true
  ["ipparse.lib.hkdf"]: true
  ["ipparse.lib.crypto.backend.lunatik"]: true
}
FUN_EXEMPT = {
  ["ipparse.fun"]: true
  ["ipparse.fun.tables"]: true
  ["ipparse.fun.memo"]: true
  ["ipparse.fun.iter"]: true
  ["ipparse.fun.protected"]: true
}

-- Facade and heavy submodules, not loaded by protocol modules. Source depth is
-- 0–1 for the facade and `protected`; bytecode loads from depth ≥ 12.
REQUIRED_DEPTH_OVERRIDES = {
  ["ipparse.fun"]: 0
  ["ipparse.fun.iter"]: 0
  ["ipparse.fun.protected"]: 0
  ["ipparse.fun.memo"]: 0
}

for i = 1, #ENTRY_MODULES
  mod = ENTRY_MODULES[i]
  max_depth = 0
  skipped = false
  skip_err = nil
  first_err = nil
  first_fail_depth = nil
  ok0, err0 = probe mod, 0
  if not ok0
    first_err = err0
    first_fail_depth = 0
    if is_stack_error err0
      max_depth = 0
    else
      skipped = true
      skip_err = err0
  if not skipped
    for d = 1, MAX_PROBE
      ok, err = probe mod, d
      if ok
        max_depth = d
      else
        if first_err == nil
          first_err = err
          first_fail_depth = d
        break

  -- Base-first guard: every entry module must load the shared base `ipparse`
  -- first, and a protocol module must not drag in the heavy `ipparse.fun`
  -- facade or its submodules. See AGENTS.md "Kernel stack budget".
  base_err = nil
  exempt_base = BASE_EXEMPT[mod] or false
  exempt_fun = FUN_EXEMPT[mod] or false
  unload_ipparse!
  ok_mod, err_mod = pcall require, mod
  if not ok_mod
    base_err = "reload failed: #{truncate err_mod}"
  else
    if not exempt_base and package.loaded["ipparse"] == nil
      base_err = "did not load ipparse first"
    if not exempt_fun
      for k = 1, #HEAVY_FUN
        if package.loaded[HEAVY_FUN[k]] != nil
          base_err = "pulled in #{HEAVY_FUN[k]}"
          break
  unload_ipparse!

  if first_err != nil
    stop_kind = is_stack_error(first_err) and "stack" or "other"
    print "CANARY\t#{mod}\tmax_depth=#{max_depth}\tstop=#{stop_kind}\t#{truncate first_err}"
  elseif max_depth >= MAX_PROBE
    print "CANARY\t#{mod}\tmax_depth>=#{MAX_PROBE}"
  else
    print "CANARY\t#{mod}\tmax_depth=#{max_depth}"
  if skipped
    print "SKIP\t#{mod}\t#{skip_err}"
  else
    total += 1
    required_depth = REQUIRED_DEPTH_OVERRIDES[mod]
    if required_depth == nil
      required_depth = REQUIRED_DEPTH
    non_stack_fail = first_err != nil and first_fail_depth >= 1 and not is_stack_error(first_err)
    if base_err != nil
      print "FAIL\tstack canary: #{mod} #{base_err}"
    elseif non_stack_fail
      print "FAIL\tstack canary: #{mod} failed at depth #{first_fail_depth} with a non-stack error: #{first_err}"
    elseif max_depth >= required_depth
      pass += 1
      print "PASS\tstack canary: #{mod} loads from depth #{max_depth}"
    else
      print "FAIL\tstack canary: #{mod} loads from depth #{max_depth} only (need #{required_depth})"
    if min_max == nil or max_depth < min_max
      min_max = max_depth

if min_max == nil
  min_max = 0
print "==> Stack canary: #{pass}/#{total}, min max_depth=#{min_max}"
unload_ipparse!
