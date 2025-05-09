--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TLS Server Name Extension Parsing and Packing Module
-- This module provides utilities for parsing and packing the TLS Server Name extension,
-- specifically handling the ServerNameList structure as defined in RFC 6066.
-- The extension type itself (0x0000 for server_name) is assumed to be handled
-- by a general TLS extension parsing mechanism. This module parses the `extension_data`
-- for the server_name extension.
--
-- ### Features
--
-- - Parse and pack the ServerNameList structure.
-- - Handles multiple ServerName entries within the list.
--
-- ### TLS Server Name Extension Structure (content of extension_data)
--
-- ```
-- ServerNameList {
--   server_name_list_length (16): Total length of all ServerName entries that follow.
--   server_name_list (variable): Sequence of one or more ServerName entries.
-- }
--
-- ServerNameEntry (for host_name) {
--   name_type (8): NameType (e.g., 0x00 for host_name).
--   name_length (16): Length of the following name data.
--   name (variable): The actual hostname string (e.g., "example.com").
-- }
-- ```
-- The object returned by `parse` represents the `ServerNameList` and contains a `names` field,
-- which is a list of parsed `ServerNameEntry` objects. Each entry object has `type` and `name` fields.
--
-- References:
--
-- - RFC 6066: Transport Layer Security (TLS) Extensions
--
-- @module tls.handshake.extension.server_name

pack: sp, unpack: su = string
:concat = table
:bidirectional,:zero_indexed = require"ipparse.fun"

--- Packs a single ServerName entry (NameType, NameLength, NameData).
-- @treturn string Binary string for the packed entry.
pack_entry = => sp ">B s2", @type, @name

_mt_entry =
  --- Converts the ServerName entry object to a binary string.
  -- @treturn string Binary string representing the entry.
  __tostring: pack_entry

--- Parses a single ServerName entry (NameType, NameLength, NameData) from a binary string.
-- @tparam[opt=1] number off Offset to start parsing from within `data`.
-- @treturn table Parsed ServerName entry object {type, name}, or nil on error.
-- @treturn number The next offset after parsing the entry.
-- @treturn string|nil Error message if parsing failed.
parse_entry = (off=1) =>
  name_type, name, _off = su ">B s2", @, off
  setmetatable({type: name_type, :name}, _mt_entry), _off

--- Packs a TLS ServerNameList (the content of the server_name extension) into a binary string.
-- Constructs the binary representation of the ServerNameList.
-- @treturn string Binary string representing the packed ServerNameList.
pack = => sp ">s2", @names and concat([pack_entry entry for entry in *@names]) or ""

_mt =
  --- Converts the ServerNameList object to a binary string.
  -- @treturn string Binary string representing the ServerNameList.
  __tostring: pack

--- Parses a binary string (the content of a server_name extension) into a ServerNameList structure.
-- Extracts the ServerNameListLength and then parses each ServerName entry within the list.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed ServerNameList as a table, with a `names` field containing a list of entry objects.
--                 Returns nil on critical parsing errors (e.g., insufficient initial data).
-- @treturn number The next offset after parsing the entire list (or up to an error).
-- @treturn string|nil Error message if parsing failed.
parse = (off=1) =>
  -- The ServerNameList itself is prefixed by a 2-byte length.
  len, _off = su ">H", @, off
  end_offset = _off + len
  names = {}
  ok = true
  while _off < end_offset
    -- If parse_entry fails due to insufficient data, su() will raise an error.
    ok, entry, _off = pcall parse_entry, @, _off
    if not ok
      print entry
      break
    names[#names+1] = entry
  setmetatable({:names, name: (names[1] and names[1].name), incomplete: not ok}, _mt), _off

name_types = bidirectional zero_indexed {"HOST_NAME"}

:parse, :pack, :parse_entry, :pack_entry, :name_types
