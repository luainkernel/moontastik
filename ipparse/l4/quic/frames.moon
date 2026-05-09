--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Frame Parsing and Packing Module
-- This module provides utilities for parsing and packing QUIC frames.
-- It supports all standard QUIC frame types including CRYPTO, STREAM, ACK, and control frames.
--
-- ### Features
-- - Parse and pack QUIC frames from decrypted packet payload
-- - Support for variable-length integer encoding (VarInt)
-- - Handle all frame types defined in RFC 9000
-- - Frame iteration and validation
--
-- ### QUIC Frame Structure
-- ```
-- Frame {
--   type (variable): Frame type as VarInt
--   type_specific_fields (variable): Fields specific to frame type
--   data (variable): Frame payload data
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module l4.quic.frames

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bidirectional = require"ipparse.fun"
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"

--- QUIC Frame Types
-- Mapping of frame type codes to their names
frame_types = bidirectional {
  [0x00]: "PADDING"
  [0x01]: "PING"
  [0x02]: "ACK"
  [0x03]: "ACK_ECN"
  [0x04]: "RESET_STREAM"
  [0x05]: "STOP_SENDING"
  [0x06]: "CRYPTO"
  [0x07]: "NEW_TOKEN"
  [0x08]: "STREAM"
  [0x09]: "STREAM"
  [0x0a]: "STREAM"
  [0x0b]: "STREAM"
  [0x0c]: "STREAM"
  [0x0d]: "STREAM"
  [0x0e]: "STREAM"
  [0x0f]: "STREAM"
  [0x10]: "MAX_DATA"
  [0x11]: "MAX_STREAM_DATA"
  [0x12]: "MAX_STREAMS_BIDI"
  [0x13]: "MAX_STREAMS_UNI"
  [0x14]: "DATA_BLOCKED"
  [0x15]: "STREAM_DATA_BLOCKED"
  [0x16]: "STREAMS_BLOCKED_BIDI"
  [0x17]: "STREAMS_BLOCKED_UNI"
  [0x18]: "NEW_CONNECTION_ID"
  [0x19]: "RETIRE_CONNECTION_ID"
  [0x1a]: "PATH_CHALLENGE"
  [0x1b]: "PATH_RESPONSE"
  [0x1c]: "CONNECTION_CLOSE"
  [0x1d]: "CONNECTION_CLOSE_APP"
  [0x1e]: "HANDSHAKE_DONE"
}

--- Parses a QUIC variable-length integer (VarInt)
-- VarInt encoding uses the first two bits to indicate length:
-- 00xxxxxx = 1 byte (0-63)
-- 01xxxxxx xxxxxxxx = 2 bytes (0-16383)
-- 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx = 4 bytes (0-1073741823)
-- 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx = 8 bytes
-- @tparam string data The binary data containing the VarInt
-- @tparam number offset Starting offset in the data
-- @treturn number The parsed integer value
-- @treturn number Next offset after the VarInt
parse_varint = (data, offset) ->
  return nil, offset if offset > #data

  first_byte = su "B", data, offset

  switch rshift(first_byte, 6)
    when 0  -- 1 byte
      first_byte, offset + 1
    when 1  -- 2 bytes
      return nil, offset if offset + 1 > #data
      value = su ">H", data, offset
      band(value, 0x3FFF), offset + 2
    when 2  -- 4 bytes
      return nil, offset if offset + 3 > #data
      value = su ">I4", data, offset
      band(value, 0x3FFFFFFF), offset + 4
    when 3  -- 8 bytes
      return nil, offset if offset + 7 > #data
      high, low = su ">I4I4", data, offset
      (band(high, 0x3FFFFFFF) * 4294967296) + low, offset + 8

need_bytes = (data, offset, len) ->
  return false if offset < 1 or len < 0
  (offset + len - 1) <= #data

parse_varint_required = (data, offset, field_name) ->
  value, next_off = parse_varint data, offset
  return nil, offset, "truncated #{field_name}" if value == nil
  value, next_off

--- Encodes a number as a QUIC variable-length integer (VarInt)
-- @tparam number value The integer value to encode
-- @treturn string Binary string containing the encoded VarInt
encode_varint = (value) ->
  if value < 64
    sp "B", value
  elseif value < 16384
    sp ">H", bor(0x4000, value)
  elseif value < 1073741824
    -- bor(0x80000000, value) produces a negative int32 which confuses write_uint
    -- encode manually: top 2 bits = 10, remaining 30 bits = value
    string.char(
      bor(0x80, band(rshift(value, 24), 0x3F))
      band(rshift(value, 16), 0xFF)
      band(rshift(value, 8), 0xFF)
      band(value, 0xFF)
    )
  else
    high = math.floor(value / 4294967296)
    low = value % 4294967296
    -- Same issue: encode manually with top 2 bits = 11
    string.char(
      bor(0xC0, band(math.floor(high / 16777216), 0x3F))
      band(math.floor(high / 65536), 0xFF)
      band(math.floor(high / 256), 0xFF)
      band(high, 0xFF)
      band(math.floor(low / 16777216), 0xFF)
      band(math.floor(low / 65536), 0xFF)
      band(math.floor(low / 256), 0xFF)
      band(low, 0xFF)
    )

--- Parses a PADDING frame
-- PADDING frames consist only of the frame type (0x00)
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed PADDING frame
-- @treturn number Next offset after the frame
parse_padding_frame = (data, offset) ->
  {type: 0x00, name: "PADDING"}, offset

--- Parses a PING frame
-- PING frames consist only of the frame type (0x01)
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed PING frame
-- @treturn number Next offset after the frame
parse_ping_frame = (data, offset) ->
  {type: 0x01, name: "PING"}, offset

--- Parses an ACK frame
-- ACK frames contain acknowledgment information for received packets
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @tparam number frame_type Frame type (0x02 or 0x03 for ACK_ECN)
-- @treturn table Parsed ACK frame
-- @treturn number Next offset after the frame
parse_ack_frame = (data, offset, frame_type) ->
  largest_acked, offset, err = parse_varint_required data, offset, "ACK largest_acked"
  return nil, offset, err unless largest_acked != nil
  ack_delay, offset, err = parse_varint_required data, offset, "ACK ack_delay"
  return nil, offset, err unless ack_delay != nil
  ack_range_count, offset, err = parse_varint_required data, offset, "ACK ack_range_count"
  return nil, offset, err unless ack_range_count != nil
  first_ack_range, offset, err = parse_varint_required data, offset, "ACK first_ack_range"
  return nil, offset, err unless first_ack_range != nil

  ack_ranges = {}
  for i = 1, ack_range_count
    gap, offset, err = parse_varint_required data, offset, "ACK gap[#{i}]"
    return nil, offset, err unless gap != nil
    ack_range_len, offset, err = parse_varint_required data, offset, "ACK range_length[#{i}]"
    return nil, offset, err unless ack_range_len != nil
    ack_ranges[#ack_ranges + 1] = {gap: gap, length: ack_range_len}

  frame = {
    type: frame_type
    name: frame_type == 0x02 and "ACK" or "ACK_ECN"
    :largest_acked, :ack_delay, :ack_range_count, :first_ack_range, :ack_ranges
  }

  -- Parse ECN counts if this is an ACK_ECN frame
  if frame_type == 0x03
    frame.ect0_count, offset, err = parse_varint_required data, offset, "ACK_ECN ect0_count"
    return nil, offset, err unless frame.ect0_count != nil
    frame.ect1_count, offset, err = parse_varint_required data, offset, "ACK_ECN ect1_count"
    return nil, offset, err unless frame.ect1_count != nil
    frame.ecn_ce_count, offset, err = parse_varint_required data, offset, "ACK_ECN ecn_ce_count"
    return nil, offset, err unless frame.ecn_ce_count != nil

  frame, offset

--- Parses a CRYPTO frame
-- CRYPTO frames contain TLS handshake data
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed CRYPTO frame with TLS data
-- @treturn number Next offset after the frame
parse_crypto_frame = (data, offset) ->
  crypto_offset, offset, err = parse_varint_required data, offset, "CRYPTO offset"
  return nil, offset, err unless crypto_offset != nil
  length, offset, err = parse_varint_required data, offset, "CRYPTO length"
  return nil, offset, err unless length != nil
  return nil, offset, "CRYPTO payload exceeds frame data" unless need_bytes data, offset, length

  -- Extract crypto data
  crypto_data = data\sub offset, offset + length - 1

  frame = {
    type: 0x06
    name: "CRYPTO"
    offset: crypto_offset
    :length
    data: crypto_data
  }

  frame, offset + length

--- Parses a STREAM frame
-- STREAM frames contain application data for a specific stream
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @tparam number frame_type Frame type (0x08-0x0f, different bits indicate presence of fields)
-- @treturn table Parsed STREAM frame
-- @treturn number Next offset after the frame
parse_stream_frame = (data, offset, frame_type) ->
  stream_id, offset, err = parse_varint_required data, offset, "STREAM id"
  return nil, offset, err unless stream_id != nil

  -- Parse optional offset field (bit 2 of frame type)
  stream_offset = 0
  if band(frame_type, 0x04) != 0
    stream_offset, offset, err = parse_varint_required data, offset, "STREAM offset"
    return nil, offset, err unless stream_offset != nil

  -- Parse optional length field (bit 1 of frame type)
  local length
  if band(frame_type, 0x02) != 0
    length, offset, err = parse_varint_required data, offset, "STREAM length"
    return nil, offset, err unless length != nil
  else
    -- Length extends to end of packet if not specified
    length = #data - offset + 1
  return nil, offset, "STREAM payload exceeds frame data" unless need_bytes data, offset, length

  -- Extract stream data
  stream_data = data\sub offset, offset + length - 1

  frame = {
    type: frame_type
    name: "STREAM"
    id: stream_id
    offset: stream_offset
    :length
    data: stream_data
    fin: band(frame_type, 0x01) != 0  -- FIN bit (bit 0)
  }

  frame, offset + length

--- Parses a NEW_TOKEN frame
-- NEW_TOKEN frames provide tokens for future connection attempts
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed NEW_TOKEN frame
-- @treturn number Next offset after the frame
parse_new_token_frame = (data, offset) ->
  token_length, offset, err = parse_varint_required data, offset, "NEW_TOKEN length"
  return nil, offset, err unless token_length != nil
  return nil, offset, "NEW_TOKEN payload exceeds frame data" unless need_bytes data, offset, token_length
  token = data\sub offset, offset + token_length - 1

  frame = {
    type: 0x07
    name: "NEW_TOKEN"
    token_length: token_length
    :token
  }

  frame, offset + token_length

--- Parses a RESET_STREAM frame (0x04)
parse_reset_stream_frame = (data, offset) ->
  stream_id, offset, err = parse_varint_required data, offset, "RESET_STREAM id"
  return nil, offset, err unless stream_id != nil
  app_error_code, offset, err = parse_varint_required data, offset, "RESET_STREAM app_error_code"
  return nil, offset, err unless app_error_code != nil
  final_size, offset, err = parse_varint_required data, offset, "RESET_STREAM final_size"
  return nil, offset, err unless final_size != nil
  {type: 0x04, name: "RESET_STREAM", :stream_id, :app_error_code, :final_size}, offset

--- Parses a STOP_SENDING frame (0x05)
parse_stop_sending_frame = (data, offset) ->
  stream_id, offset, err = parse_varint_required data, offset, "STOP_SENDING id"
  return nil, offset, err unless stream_id != nil
  app_error_code, offset, err = parse_varint_required data, offset, "STOP_SENDING app_error_code"
  return nil, offset, err unless app_error_code != nil
  {type: 0x05, name: "STOP_SENDING", :stream_id, :app_error_code}, offset

--- Parses a MAX_DATA frame (0x10)
parse_max_data_frame = (data, offset) ->
  maximum_data, offset, err = parse_varint_required data, offset, "MAX_DATA maximum_data"
  return nil, offset, err unless maximum_data != nil
  {type: 0x10, name: "MAX_DATA", :maximum_data}, offset

--- Parses a MAX_STREAM_DATA frame (0x11)
parse_max_stream_data_frame = (data, offset) ->
  stream_id, offset, err = parse_varint_required data, offset, "MAX_STREAM_DATA stream_id"
  return nil, offset, err unless stream_id != nil
  maximum_stream_data, offset, err = parse_varint_required data, offset, "MAX_STREAM_DATA maximum_stream_data"
  return nil, offset, err unless maximum_stream_data != nil
  {type: 0x11, name: "MAX_STREAM_DATA", :stream_id, :maximum_stream_data}, offset

--- Parses MAX_STREAMS frames (0x12 bidi, 0x13 uni)
parse_max_streams_frame = (data, offset, frame_type) ->
  maximum_streams, offset, err = parse_varint_required data, offset, "MAX_STREAMS maximum_streams"
  return nil, offset, err unless maximum_streams != nil
  name = frame_type == 0x12 and "MAX_STREAMS_BIDI" or "MAX_STREAMS_UNI"
  {type: frame_type, :name, :maximum_streams}, offset

--- Parses a DATA_BLOCKED frame (0x14)
parse_data_blocked_frame = (data, offset) ->
  maximum_data, offset, err = parse_varint_required data, offset, "DATA_BLOCKED maximum_data"
  return nil, offset, err unless maximum_data != nil
  {type: 0x14, name: "DATA_BLOCKED", :maximum_data}, offset

--- Parses a STREAM_DATA_BLOCKED frame (0x15)
parse_stream_data_blocked_frame = (data, offset) ->
  stream_id, offset, err = parse_varint_required data, offset, "STREAM_DATA_BLOCKED stream_id"
  return nil, offset, err unless stream_id != nil
  maximum_stream_data, offset, err = parse_varint_required data, offset, "STREAM_DATA_BLOCKED maximum_stream_data"
  return nil, offset, err unless maximum_stream_data != nil
  {type: 0x15, name: "STREAM_DATA_BLOCKED", :stream_id, :maximum_stream_data}, offset

--- Parses STREAMS_BLOCKED frames (0x16 bidi, 0x17 uni)
parse_streams_blocked_frame = (data, offset, frame_type) ->
  maximum_streams, offset, err = parse_varint_required data, offset, "STREAMS_BLOCKED maximum_streams"
  return nil, offset, err unless maximum_streams != nil
  name = frame_type == 0x16 and "STREAMS_BLOCKED_BIDI" or "STREAMS_BLOCKED_UNI"
  {type: frame_type, :name, :maximum_streams}, offset

--- Parses a NEW_CONNECTION_ID frame (0x18)
parse_new_connection_id_frame = (data, offset) ->
  sequence_number, offset, err = parse_varint_required data, offset, "NEW_CONNECTION_ID sequence_number"
  return nil, offset, err unless sequence_number != nil
  retire_prior_to, offset, err = parse_varint_required data, offset, "NEW_CONNECTION_ID retire_prior_to"
  return nil, offset, err unless retire_prior_to != nil
  return nil, offset, "truncated NEW_CONNECTION_ID cid_length" unless need_bytes data, offset, 1
  cid_length = su "B", data, offset
  offset += 1
  return nil, offset, "NEW_CONNECTION_ID connection_id exceeds frame data" unless need_bytes data, offset, cid_length
  connection_id = data\sub offset, offset + cid_length - 1
  offset += cid_length
  return nil, offset, "NEW_CONNECTION_ID stateless_reset_token exceeds frame data" unless need_bytes data, offset, 16
  stateless_reset_token = data\sub offset, offset + 15
  offset += 16
  {
    type: 0x18, name: "NEW_CONNECTION_ID"
    :sequence_number, :retire_prior_to, :cid_length, :connection_id, :stateless_reset_token
  }, offset

--- Parses a RETIRE_CONNECTION_ID frame (0x19)
parse_retire_connection_id_frame = (data, offset) ->
  sequence_number, offset, err = parse_varint_required data, offset, "RETIRE_CONNECTION_ID sequence_number"
  return nil, offset, err unless sequence_number != nil
  {type: 0x19, name: "RETIRE_CONNECTION_ID", :sequence_number}, offset

--- Parses a PATH_CHALLENGE frame (0x1a)
parse_path_challenge_frame = (data, offset) ->
  return nil, offset, "PATH_CHALLENGE requires 8 bytes" unless need_bytes data, offset, 8
  path_data = data\sub offset, offset + 7
  {type: 0x1a, name: "PATH_CHALLENGE", data: path_data}, offset + 8

--- Parses a PATH_RESPONSE frame (0x1b)
parse_path_response_frame = (data, offset) ->
  return nil, offset, "PATH_RESPONSE requires 8 bytes" unless need_bytes data, offset, 8
  path_data = data\sub offset, offset + 7
  {type: 0x1b, name: "PATH_RESPONSE", data: path_data}, offset + 8

--- Parses a CONNECTION_CLOSE frame (0x1c or 0x1d)
parse_connection_close_frame = (data, offset, frame_type) ->
  error_code, offset, err = parse_varint_required data, offset, "CONNECTION_CLOSE error_code"
  return nil, offset, err unless error_code != nil
  local frame_type_field
  if frame_type == 0x1c
    frame_type_field, offset, err = parse_varint_required data, offset, "CONNECTION_CLOSE frame_type"
    return nil, offset, err unless frame_type_field != nil
  reason_length, offset, err = parse_varint_required data, offset, "CONNECTION_CLOSE reason_length"
  return nil, offset, err unless reason_length != nil
  return nil, offset, "CONNECTION_CLOSE reason exceeds frame data" unless need_bytes data, offset, reason_length
  reason_phrase = data\sub offset, offset + reason_length - 1
  name = frame_type == 0x1c and "CONNECTION_CLOSE" or "CONNECTION_CLOSE_APP"
  {
    type: frame_type, :name, :error_code, frame_type: frame_type_field
    :reason_length, :reason_phrase
  }, offset + reason_length

--- Parses a HANDSHAKE_DONE frame (0x1e) — no fields
parse_handshake_done_frame = (data, offset) ->
  {type: 0x1e, name: "HANDSHAKE_DONE"}, offset

--- Parses a generic frame header and delegates to specific parsers.
-- Returns nil only when offset is past end-of-data; returns an UNKNOWN frame
-- for unrecognised types (advances by 1 byte to avoid infinite loops).
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed frame object
-- @treturn number Next offset after the frame
parse_frame = (data, offset) ->
  return nil, offset if offset > #data

  frame_type, new_offset = parse_varint data, offset
  return nil, offset, "truncated frame type varint" unless frame_type

  parser = switch frame_type
    when 0x00  then parse_padding_frame
    when 0x01  then parse_ping_frame
    when 0x02, 0x03 then (d, o) -> parse_ack_frame d, o, frame_type
    when 0x04  then parse_reset_stream_frame
    when 0x05  then parse_stop_sending_frame
    when 0x06  then parse_crypto_frame
    when 0x07  then parse_new_token_frame
    when 0x10  then parse_max_data_frame
    when 0x11  then parse_max_stream_data_frame
    when 0x12, 0x13 then (d, o) -> parse_max_streams_frame d, o, frame_type
    when 0x14  then parse_data_blocked_frame
    when 0x15  then parse_stream_data_blocked_frame
    when 0x16, 0x17 then (d, o) -> parse_streams_blocked_frame d, o, frame_type
    when 0x18  then parse_new_connection_id_frame
    when 0x19  then parse_retire_connection_id_frame
    when 0x1a  then parse_path_challenge_frame
    when 0x1b  then parse_path_response_frame
    when 0x1c, 0x1d then (d, o) -> parse_connection_close_frame d, o, frame_type
    when 0x1e  then parse_handshake_done_frame
    else
      if frame_type >= 0x08 and frame_type <= 0x0f
        (d, o) -> parse_stream_frame d, o, frame_type
      else
        nil

  return {type: frame_type, name: "UNKNOWN"}, new_offset unless parser
  frame, parsed_off, err = parser data, new_offset
  return nil, offset, err unless frame
  frame, parsed_off

--- Iterates over all frames in a decrypted QUIC packet payload
-- @tparam string payload_data The decrypted packet payload containing frames
-- @treturn function Iterator function that returns each parsed frame
iter_frames = (payload_data) ->
  offset = 1
  ->
    return nil if offset > #payload_data

    frame, new_offset = parse_frame payload_data, offset
    return nil unless frame
    offset = new_offset
    frame

--- Validates that frame data is complete and well-formed
-- @tparam string payload_data The decrypted packet payload
-- @treturn boolean True if all frames are valid
-- @treturn string Error message if validation fails
validate_frames = (payload_data) ->
  offset = 1
  frame_count = 0

  while offset <= #payload_data
    frame, new_offset, err = parse_frame payload_data, offset
    unless frame
      return false, err or "Failed to parse frame at offset #{offset}"

    if new_offset <= offset
      return false, "Frame parser did not advance at offset #{offset}"

    offset = new_offset
    frame_count += 1

    -- Prevent infinite loop with reasonable limit
    if frame_count > 1000
      return false, "Too many frames (possible parsing error)"

  true, "#{frame_count} frames validated"

:parse_frame, :parse_crypto_frame, :parse_stream_frame, :parse_ack_frame, :iter_frames, :validate_frames, :parse_varint, :encode_varint, :frame_types
