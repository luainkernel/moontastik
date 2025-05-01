-- Small library for basic functional programming primitives
:sort = table
unpack or= table.unpack

memo = =>
  tmp = __mode: "kv"
  setmetatable tmp, tmp
  (x) ->
    return @(x) if not x
    r = tmp[x] or {@ x}
    tmp[x] = r if x
    unpack r

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

bidirectional = =>
  @[v] = k for k, v in pairs @
  @

zero_indexed = =>
  @[i] = @[i+1] for i = 0, #@
  @

local iter

wrap = =>
  _ =
    __call: @
    __index: iter
  setmetatable _, _

iter =
  __call: (t, step=1, i=(step > 0 and step or #t)) =>
    i -= step
    wrap ->
      i += step
      t[i]

  any: (fn) => @getn 1, fn

  each: (fn) =>
    while true
      if v = @!
        fn v
      else break

  getn: (n, fn) =>
    i = 1
    while true
      if v = @!
        if fn v
          return v if i == n
          i += 1
      else break

  map: (fn) =>
    wrap ->
      if v = @!
        fn v

  imap: (fn) =>
    i = 0
    wrap ->
      if v = @!
        i += 1
        fn v, i

  filter: (fn) =>
    wrap ->
      while true
        if v = @!
          if fn v
            return v
        else return nil

  take: (n) =>
    i = 0
    wrap ->
      i += 1
      @! if i <= n

  toarray: =>
    t = {}
    while true
      if v = @!
        t[#t+1] = v
      else break
    t

  reduce: (fn, initial) =>
    accum = initial or @!
    for v in @
      accum = fn accum, v
    accum

iter.__index = iter
setmetatable iter, iter

generate = (fn) -> wrap -> fn!

range = (max, step) =>
  step or= 1
  i = max and @-step or 0
  max or= @
  wrap ->
    i += step
    i if i <= max

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

protected = (fn, op) -> (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ->
  ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall (
    -> fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
  ), (err) ->
    print err
    print debug.traceback!
    op! if op
  if ok
    a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z


_ = {
  :bidirectional, :memo, :memoN, :iter, :wrap, :range, :opairs, :generate, :zero_indexed, :protected
  __index: (_, k) ->
    -- Importing the names of iter’s methods will return table / iterator wrapper.
    -- Example:
    -- > require"fun".map t, => 2*@
    -- is equivalent to
    -- > require"fun".iter(t)\map => 2*@
    fn = (...) =>
      o = (type(@) == 'table' and iter or wrap) @
      o[k] o, ...
    _[k] = fn
    fn
}

setmetatable _, _

