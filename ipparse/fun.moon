-- Small library for basic functional programming primitives:
-- map, filter, take, reduce


local iter

wrap = =>
  _ =
    __call: @
    __index: iter
  setmetatable _, _

iter =
  __call: (t) =>
    i = 0
    wrap ->
      i += 1
      t[i]

  each: (fn) =>
    while true
      if v = @!
        fn v
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
        else return

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

imap = (fn) => iter(@)\map fn

map = (fn) => iter(@)\map fn

filter = (fn) => iter(@)\filter fn

take = (n) => iter(@)\take n

reduce = (...) => iter(@)\reduce ...

generate = (fn) -> wrap -> fn!

range = (max, step) =>
  step or= 1
  i = max and @-step or 0
  max or= @
  wrap ->
    i += step
    i if i <= max

:iter, :wrap, :imap, :map, :filter, :take, :reduce, :generate, :range
