--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Version negotiation packets
pack: sp, unpack: su = require "ipparse.lib.pack_compat"

version = 0

pack = =>
  parts = {}
  for v in *@supported_versions
    parts[#parts + 1] = sp ">I4", v
  table.concat parts

_mt =
  __tostring: pack

parse_payload = (off=1) =>
  supported_versions = {}
  while off + 3 <= #@
    v, _off = su ">I4", @, off
    supported_versions[#supported_versions + 1] = v
    off = _off
  setmetatable({:supported_versions}, _mt), off

:version, :pack, :parse_payload
