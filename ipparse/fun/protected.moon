--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Protected calls with optional error tracing.
-- Split out of `ipparse.fun` so the other primitives can be loaded without
-- this module.
-- @module fun.protected

M = {}

-- Detected once at load time: xpcall forwards extra arguments on Lua 5.2+ and
-- LuaJIT, but not on Lua 5.1 PUC. Kept as a flat local so `protected` does not
-- need a nested probe function.
xpcall_passes_args = select(2, xpcall(((x) -> x), (-> true), true)) == true

--- Wraps a function call in `xpcall` to catch errors.
-- If an error occurs, it prints the error. When `M.leak_debug` is true, it also prints a full traceback.
--- Calls an optional `op` function on error.
--
-- Implementation note: arguments and results are threaded through 26 explicit
-- locals (a–z) instead of varargs. This is deliberate: protected functions sit
-- on the hot path (per-packet), and a vararg implementation would allocate a
-- table and call `unpack` on every invocation. The trade-off is a hard limit
-- of 26 arguments and 26 return values.
--
-- Implementation note: the error handler and the returned function are defined
-- as flat locals rather than inline in the `xpcall` call. The Lua parser is
-- recursive in C, and Lunatik runs on a 16 KiB kernel stack with a C-call
-- guard derived from the stack actually consumed: inline function expressions
-- nested two deep here pushed `require "ipparse.fun"` over that guard when the
-- module was loaded one `require` level deeper than the top level. Defining
-- them at block level reduces the parser's C recursion; the API and semantics
-- are unchanged.
--
-- Implementation note: when the runtime's `xpcall` forwards extra arguments
-- (`xpcall_passes_args`, true on Lua 5.2+/LuaJIT), `fn` is passed to `xpcall`
-- directly with its arguments, avoiding the per-call `call` closure. On Lua
-- 5.1 PUC the closure form is kept as a fallback.
-- @tparam function fn
-- @tparam[opt] function op
-- @treturn function A new, protected function (max 26 args/returns).
-- @usage
-- -- The returned protected function takes:
-- -- @tparam ...any ... Arguments for the original `fn`.
-- -- @treturn ...any|nil Results from `fn` or `op` (see main description for conditions).
M.protected = (fn, op) ->
  leak_debug = M.leak_debug
  onerror = (err) ->
    print err
    print debug.traceback! if leak_debug
    op! if op
  if xpcall_passes_args
    (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ->
      ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall fn, onerror, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
      if ok
        a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
  else
    (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ->
      call = -> fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
      ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall call, onerror
      if ok
        a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z

M
