--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- DNS Parsing and Packing Module
-- This module provides utilities for parsing, packing, and manipulating DNS messages.
-- It supports DNS header parsing, question and resource record handling, and EDNS options.
--
-- ### Features
-- - Parse and pack DNS headers, questions, and resource records.
-- - Handle DNS label compression and decompression.
-- - Support for EDNS options and extended DNS error codes.
--
-- ### DNS Message Structure
-- A DNS message consists of the following sections:
--
-- 1. **Header**:
--    - Transaction ID (16 bits): Identifies the DNS query/response pair.
--    - Flags (16 bits): Contains fields such as `qr`, `opcode`, `aa`, `tc`, `rd`, `ra`, `z`, and `rcode`.
--    - QDCOUNT (16 bits): Number of entries in the Question section.
--    - ANCOUNT (16 bits): Number of entries in the Answer section.
--    - NSCOUNT (16 bits): Number of entries in the Authority section.
--    - ARCOUNT (16 bits): Number of entries in the Additional section.
--
-- 2. **Question Section**:
--    - QNAME (variable length): Fully qualified domain name (FQDN) being queried.
--    - QTYPE (16 bits): Type of query (e.g., `A`, `AAAA`, `MX`).
--    - QCLASS (16 bits): Class of query (e.g., `IN` for Internet).
--
-- 3. **Answer, Authority, and Additional Sections**:
--    - NAME (variable length): Domain name to which the resource record pertains.
--    - TYPE (16 bits): Type of resource record (e.g., `A`, `AAAA`, `MX`).
--    - CLASS (16 bits): Class of resource record (e.g., `IN` for Internet).
--    - TTL (32 bits): Time-to-live for the resource record.
--    - RDLENGTH (16 bits): Length of the RDATA field.
--    - RDATA (variable length): Resource data (e.g., IP address for `A` records).
--
-- ### DNS Label Compression
-- DNS messages use label compression to reduce message size. A label can either be:
-- 1. **Normal Label**:
--    - A sequence of characters prefixed by its length.
-- 2. **Compressed Label**:
--    - A pointer to a previously defined label in the message.
--    - Compressed labels are identified by the first two bits of the label length field being set to `11`.
--
-- This module provides utilities to parse and handle both normal and compressed labels. The `label` function parses a single label, while the `labels` function parses a sequence of labels into a fully qualified domain name (FQDN).
--
-- ### EDNS Options
-- EDNS (Extension Mechanisms for DNS) extends the capabilities of DNS by allowing additional options to be included in DNS messages.
-- These options are encoded in OPT pseudo-resource records in the Additional section of a DNS message.
--
-- Common EDNS options supported by this module:
-- - **Client Subnet (Code 8)**:
--   - Fields: `family`, `source_netmask`, `scope_netmask`, `subnet`.
--   - Used to specify the network of the client making the DNS query.
-- - **Requestor MAC (Code 65001)**:
--   - Fields: `mac`.
--   - Used to include the MAC address of the requestor.
-- - **Requestor MAC String (Code 65073)**:
--   - Fields: `macstr`.
--   - Similar to `Requestor MAC`, but includes the MAC address as a string.
--
-- This module provides utilities to parse and pack EDNS options, ensuring compliance with RFC 6891.
--
-- References:
-- - RFC 1035: Domain Names - Implementation and Specification
-- - RFC 6891: Extension Mechanisms for DNS (EDNS(0))
--
-- @module l7.dns

{:need_bytes} = require "ipparse"
:bidirectional, :zero_indexed = require "ipparse.fun.tables"
pack: sp, unpack: su, :sub = require "ipparse.lib.pack_compat"
:concat = table
:byte = string
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"

--- Reads a big-endian uint16 with `string.byte` (one call, no allocation).
-- The generic `su`/`string.unpack` emulation dominated the profile of a
-- response parse (one call per field, four fields per resource record).
-- @tparam string s Binary string.
-- @tparam number off 1-based offset of the first byte.
-- @treturn number The unsigned 16-bit value.
u16 = (s, off) ->
  a, b = byte s, off, off + 1
  a * 256 + b

--- Reads a big-endian uint32 with `string.byte` (one call, no allocation).
-- @tparam string s Binary string.
-- @tparam number off 1-based offset of the first byte.
-- @treturn number The unsigned 32-bit value.
u32 = (s, off) ->
  a, b, c, d = byte s, off, off + 3
  a * 16777216 + b * 65536 + c * 256 + d

--- Packs the DNS header into a binary string.
-- @tparam table self The DNS header object.
-- @treturn string Binary string representing the packed DNS header.
pack_header = =>
  (@size and sp(">H", @size) or "") .. sp ">H B B H H H H", @id, @qr_opcode_aa_tc_rd, @ra_z_rcode, @qdcount, @ancount, @nscount, @arcount

_header_mt =
  __tostring: pack_header
  __index: (flag) =>
    switch flag
      when "qr"
        band(@qr_opcode_aa_tc_rd, 0x80) ~= 0
      when "opcode"
        band(rshift(@qr_opcode_aa_tc_rd, 3), 0xf)
      when "aa"
        band(@qr_opcode_aa_tc_rd, 0x04) ~= 0
      when "tc"
        band(@qr_opcode_aa_tc_rd, 0x02) ~= 0
      when "rd"
        band(@qr_opcode_aa_tc_rd, 0x01) ~= 0
      when "ra"
        band(@ra_z_rcode, 0x80) ~= 0
      when "z"
        band(rshift(@ra_z_rcode, 4), 0x07)
      when "rcode"
        band(@ra_z_rcode, 0x0f)
  __newindex: (flag, val) =>
    switch flag
      when "qr"
        if val then @qr_opcode_aa_tc_rd = bor(@qr_opcode_aa_tc_rd, 0x80) else @qr_opcode_aa_tc_rd = band(@qr_opcode_aa_tc_rd, bnot(0x80))
      when "opcode"
        @qr_opcode_aa_tc_rd = bor(band(@qr_opcode_aa_tc_rd, bnot(0x78)), lshift(band(val, 0xf), 3))
      when "aa"
        if val then @qr_opcode_aa_tc_rd = bor(@qr_opcode_aa_tc_rd, 0x04) else @qr_opcode_aa_tc_rd = band(@qr_opcode_aa_tc_rd, bnot(0x04))
      when "tc"
        if val then @qr_opcode_aa_tc_rd = bor(@qr_opcode_aa_tc_rd, 0x02) else @qr_opcode_aa_tc_rd = band(@qr_opcode_aa_tc_rd, bnot(0x02))
      when "rd"
        if val then @qr_opcode_aa_tc_rd = bor(@qr_opcode_aa_tc_rd, 0x01) else @qr_opcode_aa_tc_rd = band(@qr_opcode_aa_tc_rd, bnot(0x01))
      when "ra"
        if val then @ra_z_rcode = bor(@ra_z_rcode, 0x80) else @ra_z_rcode = band(@ra_z_rcode, bnot(0x80))
      when "z"
        @ra_z_rcode = bor(band(@ra_z_rcode, bnot(0x70)), lshift(band(val, 0x07), 4))
      when "rcode"
        @ra_z_rcode = bor(band(@ra_z_rcode, bnot(0x0f)), band(val, 0x0f))
      else rawset @, flag, val

--- Parses a DNS header from a binary string.
-- @tparam number off The offset to start parsing from.
-- @tparam boolean is_tcp Whether the DNS message is over TCP (affects size field).
-- @treturn table Parsed DNS header as a table.
-- @treturn number The next offset after parsing.
parse_header = (off, is_tcp) =>  -- Accepts data string, offset and boolean; returns DNS header infos
  len = #@ - off + 1
  local size
  if is_tcp
    return nil, "No DNS data" if len < 2
    size = u16 @, off
    off += 2
    len -= 2
  return nil, "No DNS data" if len < 12
  id = u16 @, off
  qr_opcode_aa_tc_rd = byte @, off + 2
  ra_z_rcode = byte @, off + 3
  qdcount = u16 @, off + 4
  ancount = u16 @, off + 6
  nscount = u16 @, off + 8
  arcount = u16 @, off + 10
  data_off = off + 12
  setmetatable({
    :id, :qr_opcode_aa_tc_rd, :ra_z_rcode
    :qdcount, :ancount, :nscount, :arcount
    :off, :data_off, :size
  }, _header_mt), data_off

--- Creates a new DNS header with sensible defaults and metatable attached.
-- @tparam[opt] table opts Initial values for the header fields.
-- @treturn table A new DNS header object.
new_header = (opts) ->
  h = setmetatable { id: 0, qr_opcode_aa_tc_rd: 0, ra_z_rcode: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 }, _header_mt
  if opts
    for k, v in pairs opts
      h[k] = v
  h

local labels, label_parts, walk_name

--- Reads one label at `off` and reports its segment (or resolves a pointer).
-- Internal core shared by `label`, `labels` and the single-pass name builder
-- (`name_string`). Returns:
--
--   * terminator (0x00): `(next_off, nil, nil, nil, false)`;
--   * ordinary label:    `(next_off, segment, nil, nil, false)` — the segment
--     is RETURNED, not appended, so the common path allocates no table;
--   * compression pointer: the pointed name is resolved into `parts` when the
--     caller supplies one (one table, one final `table.concat` for the whole
--     name), otherwise into a throw-away table that is joined into a single
--     segment — exactly what the original `label` did;
--   * error: `(nil, nil, err, err_off, false)` with the historical offsets.
--
-- The `seed` argument defers the allocation of the anti-loop `visited` table:
-- for the first pointer hop of a name (the common case: an answer NAME that
-- points at the QNAME) the target offset is remembered in `seed` instead of
-- a table; the table is only created if a second hop needs it. Checks,
-- limits (32 hops) and error messages are identical to the original.
-- @tparam number off Offset (1-based) of the label inside `@`
-- @tparam number l7_off Offset of the DNS message start inside `@`
-- @tparam table|nil parts Segment accumulator, or nil to receive a joined
--   segment for pointers
-- @tparam table|nil visited Offsets already resolved (anti-loop)
-- @tparam number depth Number of pointer hops already followed
-- @tparam number|nil seed Target offset of the first hop (see above)
-- @treturn number|nil Next offset, nil on error
-- @treturn string|nil Segment (nil for a terminator or an accumulated pointer)
-- @treturn string|nil Error message
-- @treturn number|nil Offset reported by `label` for that error
-- @treturn boolean `true` if the label is a compression pointer
label_parts = (off, l7_off, parts, visited, depth, seed) =>
  data_len = #@
  if off < 1 or off > data_len
    return nil, nil, "invalid label offset #{off}", off, false
  size = byte @, off
  _off = off + 1
  if size == 0  -- End of label
    return _off, nil, nil, nil, false
  if band(size, 0xC0) == 0xC0  -- DNS label compression pointer
    if _off > data_len
      return nil, nil, "truncated DNS compression pointer", off, false
    pos = byte @, _off
    ptr = lshift(band(size, 0x3F), 8) + pos
    target_off = l7_off + ptr
    if target_off < l7_off or target_off > data_len
      return nil, nil, "DNS compression pointer out of bounds (#{ptr})", _off + 1, false
    if depth >= 32
      return nil, nil, "DNS compression pointer recursion limit reached", _off + 1, false
    if (visited and visited[target_off]) or seed == target_off
      return nil, nil, "DNS compression pointer loop at #{ptr}", _off + 1, false
    v_next, seed_next = visited, seed
    if not v_next and seed_next
      v_next = { [seed_next]: true }   -- second saut : la table devient nécessaire
      seed_next = nil
    if v_next
      -- Keep the entry for the whole resolution: clearing it after the
      -- recursive call would let crafted pointer chains revisit the same
      -- offset through different paths (quadratic blow-up).
      v_next[target_off] = true
    else
      seed_next = target_off          -- premier saut : reporté, sans allocation
    -- No accumulator from the caller (`label`/`labels` want ONE joined
    -- segment): resolve into a throw-away table and join it below.
    target_parts = parts
    joined = nil
    unless target_parts
      target_parts = {}
      joined = true
    n0 = #target_parts
    _, err = walk_name @, target_off, l7_off, target_parts, v_next, depth + 1, seed_next
    return nil, nil, err, _off + 1, false if err
    -- The original stored the resolved name as ONE already-joined segment,
    -- so a pointer to an empty name contributed "" — which is what makes
    -- `concat` emit the trailing dot. Keep that exact output.
    target_parts[#target_parts + 1] = "" if #target_parts == n0
    if joined
      return _off + 1, concat(target_parts, "."), nil, nil, true
    return _off + 1, nil, nil, nil, true
  if band(size, 0xC0) == 0  -- Normal case
    if off + size > data_len
      return nil, nil, "truncated DNS label (len=#{size})", off, false
    return off + size + 1, sub(@, off + 1, off + size), nil, nil, false
  nil, nil, "invalid DNS label prefix at offset #{off}", off, false

--- Reads the whole name starting at `off`, appending every segment to `parts`.
-- Mirrors the loop of `labels` (1024 segments maximum, stop on terminator or
-- on the first pointer) but shares `parts` with the pointer resolution.
-- @tparam number off Offset of the name inside `@`
-- @tparam number l7_off Offset of the DNS message start inside `@`
-- @tparam table parts Accumulated segments (mutated in place)
-- @tparam table|nil visited Offsets already resolved (anti-loop)
-- @tparam number depth Number of pointer hops already followed
-- @tparam number|nil seed Target offset of the first hop
-- @treturn number|nil Next offset, nil on error
-- @treturn string|nil Error message
-- @treturn number|nil Offset of the failing label (contract of `labels`)
walk_name = (off, l7_off, parts, visited, depth, seed) =>
  cur = off
  n = #parts   -- compteur local : un seul `#` par nom, pas un par segment
  for i = 1, 1024  -- Arbitrary large limit to avoid infinite loops
    next_off, seg, err, _, from_ptr = label_parts @, cur, l7_off, parts, visited, depth, seed
    return nil, err, cur if err
    if seg
      n += 1
      parts[n] = seg
    elseif not from_ptr
      return next_off, nil, nil     -- terminateur de nom
    cur = next_off
    break if from_ptr
  cur, nil, nil

--- Parses a single DNS label from a binary string.
-- Handles both normal labels and compressed labels.
-- @tparam number off The offset to start parsing from.
-- @tparam[opt=1] number l7_off The layer 7 offset for label parsing (default is 1).
-- @treturn string|nil The parsed label as a string, or `nil` if the label is empty.
-- @treturn number The next offset after parsing.
-- @treturn[opt] boolean `true` if the label is compressed, `nil` otherwise.
label = (off, l7_off=1, visited=nil, depth=0) =>
  next_off, seg, err, err_off, from_ptr = label_parts @, off, l7_off, nil, visited, depth, nil
  return nil, err_off, nil, err if err
  return nil, next_off unless seg or from_ptr   -- terminateur
  return seg, next_off, true if from_ptr
  seg, next_off

--- Parses a sequence of DNS labels into a fully qualified domain name (FQDN).
-- Handles both normal and compressed labels.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @treturn table A table of parsed labels.
-- @treturn number The next offset after parsing.
labels = (off, l7_off, visited=nil, depth=0) =>
  lbls = {}
  cur = off
  for i = 1, 1024  -- Arbitrary large limit to avoid infinite loops
    -- cur is the current absolute offset in the input string (@)
    -- l7_off is the absolute offset of the start of the DNS message in @
    lbl_segment, next_parse_off, is_from_pointer, err = label @, cur, l7_off, visited, depth
    return nil, cur, err if err
    if not lbl_segment  -- fin de nom (octet 00)
      cur = next_parse_off
      break
    lbls[i] = lbl_segment
    cur = next_parse_off
    break if is_from_pointer  -- un pointeur résout le reste du nom
  lbls, cur

--- Builds the dotted form of the name starting at `off` in a single pass.
-- Internal fast path of `parse_rr`: same contract as `labels` (returns the
-- next offset, or `nil, fail_off, err`) but returns the joined name directly,
-- with one segment table and one `table.concat` for the whole name —
-- including names resolved through compression pointers, where `labels` +
-- `concat` built two tables and two strings.
--
-- With `cache` (one table per DNS message, created by `parse`), a name that
-- STARTS with a pointer is looked up by its target offset: every answer of a
-- response pointing at the QNAME then costs one `string.byte` pair and no
-- allocation at all, instead of re-walking the pointed name. Entries are
-- keyed by the offset where the name starts — a resolution is a pure
-- function of the message bytes, and the cache never outlives one `parse`.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @tparam table|nil cache Per-message name cache (see above), or nil.
-- @treturn string|nil The dotted name, or `nil` on error.
-- @treturn number The next offset after parsing.
-- @treturn string|nil The error message (third value on error).
name_string = (off, l7_off, cache) =>
  target = nil
  if cache
    size = byte @, off
    if off >= 1 and off + 1 <= #@ and band(size, 0xC0) == 0xC0
      t = l7_off + lshift(band(size, 0x3F), 8) + byte(@, off + 1)
      if t >= l7_off and t <= #@
        target = t
        hit = cache[t]
        return hit, off + 2 if hit
  parts = {}
  next_off, err, fail_off = walk_name @, off, l7_off, parts, nil, 0, nil
  return nil, fail_off, err if err
  name = concat parts, "."
  if cache
    cache[off] = name
    -- A name made of a single pointer IS the name it points at: caching the
    -- target too is what makes the following answers hit.
    cache[target] = name if target
  name, next_off

--- Packs a DNS question into a binary string.
-- @tparam table self The DNS question object.
-- @treturn string Binary string representing the packed DNS question.
pack_question = =>
  @qname .. sp ">H H", @qtype, @qclass

_question_mt = __tostring: pack_question

--- Parses a DNS question section from a binary string.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @treturn table Parsed DNS question as a table.
-- @treturn number The next offset after parsing.
--- Parses a DNS question section from a binary string.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @tparam table|nil cache Per-message name cache (cf. `parse`), or nil.
-- @treturn table Parsed DNS question as a table.
-- @treturn number The next offset after parsing.
parse_question = (off, l7_off, cache) =>
  lbls, _off, err = labels @, off, l7_off
  return nil, off, err unless lbls
  return nil, off, "truncated DNS question fields" unless need_bytes @, _off, 4
  qname = sub @, off, _off-1
  qtype = u16 @, _off
  qclass = u16 @, _off + 2
  _off += 4
  name = concat lbls, "."
  cache[off] = name if cache   -- la section answer pointe sur ce nom
  setmetatable({name: name, :qname, :qtype, :qclass, :off, end_off: _off-1}, _question_mt), _off

parse_questions = (off, qdcount, l7_off, cache) =>
  res = {}
  for i = 1, qdcount
    q, off, err = parse_question @, off, l7_off, cache
    return nil, off, err unless q
    res[i] = q
  res, off

--- Packs a DNS resource record (RR) into a binary string.
-- @tparam table self The DNS resource record object.
-- @treturn string Binary string representing the packed DNS resource record.
pack_rr = =>
  _rclass = @rclass or (@rtype == 0x29 and 0 or 1)
  _ttl = @ttl or 0
  @rname .. sp ">H H I4 s2", @rtype, _rclass, _ttl, @rdata

_rr_mt = __tostring: pack_rr

--- Parses a DNS resource record (RR) from a binary string.
-- @tparam number off The offset to start parsing from.
-- @tparam number l7_off The layer 7 offset for label parsing.
-- @tparam table|nil cache Per-message name cache (cf. `parse`), or nil.
-- @treturn table Parsed DNS resource record as a table.
-- @treturn number The next offset after parsing.
parse_rr = (off, l7_off, cache) =>
  name_str, _off, err = name_string @, off, l7_off, cache
  return nil, off, err unless name_str
  return nil, off, "truncated DNS resource record header" unless need_bytes @, _off, 10
  rname = sub @, off, _off-1
  rtype = u16 @, _off
  rclass = u16 @, _off + 2
  ttl = u32 @, _off + 4
  rdlen = u16 @, _off + 8
  _off += 10
  return nil, off, "truncated DNS resource record data" unless need_bytes @, _off, rdlen
  rdata = sub @, _off, _off + rdlen - 1
  _off += rdlen
  setmetatable({name: name_str, :rname, :rtype, :rclass, :ttl, :rdata, :off, end_off: _off-1}, _rr_mt), _off

parse_rrs = (off, count, l7_off, cache) =>
  res = {}
  for i = 1, count
    r, off, err = parse_rr @, off, l7_off, cache
    return nil, off, err unless r
    res[i] = r
  res, off

pack_opt = =>
  sp ">Hs2", @code, "#{@data}"

edns_opts = {
  [8]:     {"client_subnet",     {"family", "source_netmask", "scope_netmask", "subnet"}, ">H B B "}
  [65001]: {"requestor_mac",     {"mac"}}
  [65073]: {"requestor_mac_str", {"macstr"}}
}
edns_opts[v[1]] = k for k, v in pairs edns_opts when type(k) == "number"

_opt_mt = __tostring: pack_opt
_raw_opt_data_mt = __tostring: => @[1]
_ecs_data_mt = __tostring: => sp(">H B B ", @family, @source_netmask, @scope_netmask) .. @subnet

--- Parses an EDNS option from a binary string.
-- @tparam number off The offset to start parsing from.
-- @treturn table Parsed EDNS option as a table.
-- @treturn number The next offset after parsing.
parse_opt = (off=1) =>
  return nil, off, "truncated EDNS option header" unless need_bytes @, off, 4
  code, len, _off = su ">H H", @, off
  return nil, off, "truncated EDNS option data" unless need_bytes @, _off, len
  raw_data = sub @, _off, _off + len - 1
  _off += len
  data = nil
  if opt_parser = edns_opts[code]
    {typ, fields, fmt} = opt_parser
    if fmt and code == 8
      return nil, off, "truncated EDNS client_subnet option" unless need_bytes raw_data, 1, 4
      family, source_netmask, scope_netmask, data_off = su fmt, raw_data
      _data = {family, source_netmask, scope_netmask, sub(raw_data, data_off)}
      data = _data
    else data = {raw_data}
    data.type = typ
    data[fields[i]] = data[i] for i = 1, #fields
    setmetatable data, (fmt and code == 8 and _ecs_data_mt or _raw_opt_data_mt)
  else data = setmetatable {raw_data}, _raw_opt_data_mt
  setmetatable({:code, :len, :data}, _opt_mt), _off

--- Parses all EDNS options from a binary string.
-- @tparam string self The binary string containing the EDNS options.
-- @treturn table A table of parsed EDNS options.
parse_opts = =>
  opts, off = {}, 1
  while off <= #@
    opt, off, err = parse_opt @, off
    return nil, off, err unless opt
    opts[#opts+1] = opt
  opts

--- Packs a DNS message into a binary string.
-- @tparam table self The DNS message object.
-- @treturn string Binary string representing the packed DNS message.
pack = =>
  @header.qdcount = #@questions
  @header.ancount = #@answers
  @header.nscount = #@authorities
  @header.arcount = #@additionals
  parts = {}
  n = 1
  body_len = 0
  for q in *@questions
    s = pack_question q
    n += 1
    parts[n] = s
    body_len += #s
  for r in *@answers
    s = pack_rr r
    n += 1
    parts[n] = s
    body_len += #s
  for r in *@authorities
    s = pack_rr r
    n += 1
    parts[n] = s
    body_len += #s
  for r in *@additionals
    s = pack_rr r
    n += 1
    parts[n] = s
    body_len += #s
  @header.size = 12 + body_len if rawget @header, "size"
  parts[1] = pack_header @header
  concat parts

_mt =
  __tostring: pack
  __index: (k) => @header[k]

--- Parses a DNS message from a binary string.
-- Names resolved during this call are memoized in one per-message table
-- (only when the message carries resource records), so that every answer
-- pointing at the QNAME costs a lookup instead of a second walk.
-- @tparam number l7_off The layer 7 offset for parsing.
-- @tparam boolean is_tcp Whether the DNS message is over TCP.
-- @treturn table Parsed DNS message as a table.
-- @treturn number The next offset after parsing.
parse = (l7_off, is_tcp) =>
  header, _off_or_err = parse_header @, l7_off, is_tcp
  return nil, l7_off, _off_or_err or "No DNS data" if not header
  _off = _off_or_err
  cache = nil
  if header.ancount + header.nscount + header.arcount > 0
    cache = {}
  questions, _off, err = parse_questions @, _off, header.qdcount, l7_off, cache
  return nil, _off, err unless questions
  answers, _off, err = parse_rrs @, _off, header.ancount, l7_off, cache
  return nil, _off, err unless answers
  authorities, _off, err = parse_rrs @, _off, header.nscount, l7_off, cache
  return nil, _off, err unless authorities
  additionals, _off, err = parse_rrs @, _off, header.arcount, l7_off, cache
  return nil, _off, err unless additionals
  setmetatable({
    :header, question: questions[1]  -- RFC 9619
    :questions, :answers, :authorities, :additionals
  }, _mt), _off

classes = bidirectional {"IN", "CS", "CH", "HS", [254]: "NONE", [255]: "ANY"}

rcodes = bidirectional zero_indexed {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

opcodes = bidirectional zero_indexed {"QUERY", "IQUERY", "STATUS", "UNASSIGNED", "NOTIFY", "UPDATE"}

types = bidirectional {
  "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL",
  "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN",
  "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT",
  "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK",
  "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3",
  "NSEC3PARAM", "TLSA", "SMIMEA", "Unassigned", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY",
  "CSYNC", "ZONEMD", "SVCB", "HTTPS", "DSYNC"
  [99]: "SPF",
  [108]: "EUI48",
  [109]: "EUI64",
  [249]: "TKEY",
  [250]: "TSIG",
  [251]: "IXFR",
  [252]: "AXFR",
  [253]: "MAILB",
  [254]: "MAILA",
  [255]: "ANY",
  [256]: "URI",
  [257]: "CAA",
  [258]: "AVC",
  [259]: "DOA",
  [260]: "AMTRELAY",
  [32768]: "TA",
  [32769]: "DLV"
}

ede_codes = bidirectional zero_indexed {
  "Other"
  "Unsupported_DNSKEY_Algorithm"
  "Unsupported_DS_Digest_Type"
  "Stale_Answer"
  "Forged_Answer"
  "DNSSEC_Indeterminate"
  "DNSSEC_Bogus"
  "Signature_Expired"
  "Signature_Not_Yet_Valid"
  "DNSKEY_Missing"
  "RRSIGs_Missing"
  "No_Zone_Key_Bit_Set"
  "NSEC_Missing"
  "Cached_Error"
  "Not_Ready"
  "Blocked"
  "Censored"
  "Filtered"
  "Prohibited"
  "Stale_NXDOMAIN_Answer"
  "Not_Authoritative"
  "Not_Supported"
  "No_Reachable_Authority"
  "Network_Error"
  "Invalid_Data"
}

--- Creates a new DNS message object.
-- Initializes the DNS message object and sets its metatable.
-- @tparam table self The DNS message object.
-- @treturn table The new DNS message object.
new = =>
  @header or= new_header!
  @questions or= {}
  @answers or= {}
  @authorities or= {}
  @additionals or= {}
  setmetatable @, _mt

{
  :parse, :pack
  :parse_header, :pack_header
  :label, :labels
  :parse_question, :pack_question, :parse_questions
  :classes
  :parse_rr, :pack_rr, :parse_rrs, :rcodes, :opcodes
  :parse_opt, :parse_opts, :edns_opts
  :types, :ede_codes
  :new_header, :new
}
