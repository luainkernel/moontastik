--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- Version negotiation packets
pack: sp, unpack: su, :rep = require "ipparse.lib.pack_compat"
:remove = table

version = 0

pack = =>
  sp rep(">H", #@supported_versions), @supported_versions

_mt =
  __tostring: pack

parse_payload = (off=1) =>
  supported_versions = {su rep(">H", #@/2), @, off}
  _off = remove supported_versions
  setmetatable({:supported_versions}, _mt), _off

:version, :pack, :parse_payload
