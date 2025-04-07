if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

format: sf, rep: sr, unpack: su, :char, :sub = string
:concat = table
:opairs = require"ipparse.fun"

dump = =>
  concat ["#{k}: #{v}" for k, v in opairs @], ", "

hexdump = (off=1, len=8, cols=2, f="%.2x") =>
  octets, characters, l = {}, {}, 0
  for i = off, #@, len
    l += 1
    n = #@-off-i+1
    n = n < len and n or len
    mask = sr "B", n
    fmt = sr "#{f} ", n
    octets[l] = sf(fmt, su mask, @, i) .. sr(' ', 3*(len-n))
    characters[l] = sub concat([s > 0x20 and s < 0x7F and char(s) or "." for s in *{su mask, @, i}]), 1, -2
  if l & 1 == 1
    l += 1
    octets[l] = sr ' ', 3*len
    characters[l] = ""
  r = [ concat([octets[cols*(i-1) + j] for j = 1, 2], " ") .. "    " .. concat([characters[cols*(i-1) + j] for j = 1, 2], " ") for i = 1, l]
  "\n" .. concat r, "\n"

:dump, :hexdump
