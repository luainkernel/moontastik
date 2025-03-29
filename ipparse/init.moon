if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

format: sf, rep: sr, unpack: su, :char, :sub = string
:concat = table
:opairs = require"ipparse.fun"

dump = =>
  concat ["#{k}: #{v}" for k, v in opairs @], ", "

hexdump = (off=1, f="%.2x", len=8) =>
  r = {}
  for i = off, #@, len
    n = #@-off-i
    n = n < len and n or len
    mask = sr "B", n
    fmt = sr "#{f} ", n
    r[#r+1] = sf(fmt, su mask, @, i) .. sr(' ', 3*(len-n)) .. "    " .. sub concat([s > 0x20 and s < 0x7F and char(s) or "." for s in *{su mask, @, i}]), 1, -2
  "\n" .. concat r, "\n"

:dump, :hexdump
