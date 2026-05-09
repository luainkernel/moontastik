--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Binary pack/unpack compatibility layer.
-- This module provides a compatibility layer for binary packing and unpacking operations.
-- On runtimes with native `string.unpack`/`string.pack` (Lua 5.3+), it uses those directly.
-- On Lua 5.1/LuaJIT, it falls back to the pure Lua implementation in pack_compat_lib.
--
-- @module lib.pack_compat
-- @return table The string table with pack/unpack functions (native) or the pack_compat_lib module (fallback)

-- pack_compat.moon
-- Parse-safe entrypoint for runtimes that reject some fallback syntax/operators.

return string if string.unpack
require "ipparse.lib.pack_compat_lib"
