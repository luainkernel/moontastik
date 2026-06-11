--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TLS supported_versions Extension Parsing Module
-- Parses the `supported_versions` extension (RFC 8446 §4.2.1).
--
-- In a ClientHello, the extension data is a 1-byte-length-prefixed list of
-- 2-byte version codes. In a ServerHello/HelloRetryRequest it is a single
-- 2-byte selected version.
--
-- @module l7.tls.handshake.extension.supported_versions

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bidirectional = require "ipparse.fun"
{:need_bytes} = require "ipparse"
:concat = table

--- Known TLS/SSL version codes.
-- @field versions Bidirectional mapping of version codes and human-readable names.
versions = bidirectional {
  [0x0300]: "SSL 3.0"
  [0x0301]: "TLS 1.0"
  [0x0302]: "TLS 1.1"
  [0x0303]: "TLS 1.2"
  [0x0304]: "TLS 1.3"
}

pack_list = => sp(">B", #@versions * 2) .. concat [sp(">H", v) for v in *@versions]
pack_selected = => sp ">H", @selected

_mt_list = __tostring: pack_list
_mt_selected = __tostring: pack_selected

--- Parses the data of a supported_versions extension.
-- Detects whether the data comes from a ClientHello (list) or a
-- ServerHello (single selected version) based on its length.
-- @tparam string self The raw extension data (not the full TLS record).
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table
--   - ClientHello: `{ versions = {v1, v2, …} }` — list of offered versions.
--   - ServerHello: `{ selected = ver }` — the negotiated version.
-- @treturn number The next offset after parsing, or the input offset on truncated data.
parse = (off=1) =>
  if #@ - off + 1 == 2
    ver, _off = su ">H", @, off
    setmetatable({selected: ver}, _mt_selected), _off
  else
    return nil, off unless need_bytes @, off, 1
    len, _off = su ">B", @, off
    return nil, off unless need_bytes @, _off, len
    list = [su ">H", @, i for i = _off, _off + len - 2, 2]
    setmetatable({versions: list}, _mt_list), _off + len

:parse, :versions
