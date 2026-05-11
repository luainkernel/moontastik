--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

unpack: su, :char, :format, :gsub, :rep, :sub = string
:concat = table
:opairs = require"ipparse.fun"
require"ipparse.fun".leak_debug = leak_debug

--- Returns a string representation of the table's key-value pairs.
-- Iterates over the table and formats each key-value pair as "key: value".
-- @tparam table self The table to be dumped.
-- @treturn string A comma-separated list of key-value pairs in the format "key: value".
dump = => concat ["#{k}: #{v}" for k, v in opairs @], ", "

--- Filters a binary string, replacing non-ASCII characters with dots.
-- @tparam string s The binary string to filter.
-- @treturn string A string with non-ASCII characters replaced by dots.
filterascii = (s) -> gsub s, ".", => " " <= @ and @ <= "~" and @ or "."

--- Validates that a buffer has enough bytes from a given offset.
-- Used to prevent buffer overreads before unpack operations.
-- @tparam number off The starting offset (1-based).
-- @tparam number len The number of bytes required.
-- @treturn boolean true if the buffer has enough bytes, false otherwise.
need_bytes = (off, len) =>
  return false if off < 1 or len < 0
  (off + len - 1) <= #@


--- Converts a binary string to a hexadecimal string.
-- @tparam string s Binary string.
-- @treturn string Hexadecimal representation (lowercase).
bin2hex = (s) -> format rep("%.2x", #s), su rep("B", #s), s

--- Converts a binary string to its hexadecimal representation in chunks.
-- @tparam string self The binary string to convert.
-- @treturn string A string containing the hexadecimal representation of the input.
lbin2hex = => concat [bin2hex sub(@, i+1, i+128) for i = 0, #@-128, 128]

--- Converts a hexadecimal string to binary.
-- @tparam string hex Hexadecimal string (even length).
-- @treturn string Binary representation.
hex2bin = => gsub @, "%x%x", => char tonumber @, 16


--- Produces a formatted hexadecimal and ASCII dump of the input data.
-- Each row contains `cols` columns of `len` bytes, with both hex and ASCII representations.
-- Non-printable ASCII bytes are shown as `.` in the ASCII section.
-- The function handles incomplete rows and aligns output accordingly.
-- @tparam[opt=1] number off The starting offset in the input data.
-- @tparam[opt=8] number len The number of bytes per row.
-- @tparam[opt=2] number cols The number of columns per row.
-- @tparam[opt="%.2x"] string f The format string for each byte.
-- @treturn string A string containing the formatted hex and ASCII dump.
hexdump = (off=1, len=8, cols=2, f="%.2x") =>
  res = {}
  for i = off, #@, len * cols
    row = sub @, i, i + len * cols - 1
    hex, ascii = {}, {}
    for j = 1, #row, len
      part = sub row, j, j + len - 1
      hex[#hex+1] = format(rep(f, #part), su(rep("B", #part), part))
      ascii[#ascii+1] = filterascii part
    res[#res+1] = format("%04x: %s %s", i-1, concat(hex, " "), concat(ascii, rep(" ", len - #ascii[#ascii])))
  concat res, "\n"


:bin2hex, :lbin2hex, :dump, :filterascii, :hex2bin, :hexdump, :leak_debug, :need_bytes
