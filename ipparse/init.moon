--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

unpack: su, :char, :format, :gsub, :rep, :sub = string
:concat = table
:opairs = require"ipparse.fun"

--- Returns a string representation of the table's key-value pairs.
-- Iterates over the table and formats each key-value pair as "key: value".
-- @tparam table self The table to be dumped.
-- @treturn string A comma-separated list of key-value pairs in the format "key: value".
dump = => concat ["#{k}: #{v}" for k, v in opairs @], ", "

--- Filters a binary string, replacing non-ASCII characters with dots.
-- @tparam string self The binary string to filter.
-- @treturn string A string with non-ASCII characters replaced by dots.
filterascii = => gsub @, ".", => " " <= @ and @ <= "~" and @ or "."

--- Converts a binary string to its hexadecimal representation.
-- @tparam string self The binary string to convert.
-- @treturn string A string containing the hexadecimal representation of the input.
bin2hex = => format rep("%.2x", #@), su rep("B", #@), @

lbin2hex = => concat [bin2hex sub(@, i+1, i+128) for i = 0, #@-128, 128]

--- Converts a hexadecimal string to its binary representation.
-- @tparam string self The hexadecimal string to convert.
-- @treturn string A string containing the binary representation of the input.
hex2bin = => gsub @, "%x%x", => char tonumber @, 16


--- Produces a formatted hexadecimal and ASCII dump of the input data.
-- Each row contains `cols` columns of `len` bytes, with both hex and ASCII representations.
-- Non-printable ASCII bytes are shown as `.` in the ASCII section.
-- The function handles incomplete rows and aligns output accordingly.
-- @tparam string self The input data to be dumped.
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


:bin2hex, :lbin2hex, :dump, :filterascii, :hex2bin, :hexdump
