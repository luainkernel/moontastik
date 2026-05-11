--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_frames.moon
-- Tests for QUIC frame parsing

util = require "ipparse.lib.util"
{:test} = util
{:parse_frame, :iter_frames, :validate_frames, :encode_varint} = require "ipparse.l4.quic.frames"

-- PADDING frame (0x00)
test "frame: PADDING parsed", ->
  f, off = parse_frame "\x00", 1
  assert f.type == 0x00 and f.name == "PADDING", "expected PADDING"

-- PING frame (0x01)
test "frame: PING parsed", ->
  f, off = parse_frame "\x01", 1
  assert f.type == 0x01 and f.name == "PING", "expected PING"

-- ACK frame (0x02) — minimal: largest_acked=0, delay=0, count=0, first=0
test "frame: ACK minimal parsed", ->
  data = "\x02\x00\x00\x00\x00"  -- type + 4 VarInts of value 0
  f, _ = parse_frame data, 1
  assert f.type == 0x02 and f.name == "ACK"
  assert f.largest_acked == 0

-- CRYPTO frame (0x06)
test "frame: CRYPTO frame parsed", ->
  payload = "hello"
  -- type(0x06) + offset(0) + length(5) + data
  data = "\x06" .. encode_varint(0) .. encode_varint(#payload) .. payload
  f, _ = parse_frame data, 1
  assert f.type == 0x06 and f.name == "CRYPTO"
  assert f.data == payload, "crypto data mismatch"
  assert f.length == 5

-- STREAM frame (0x0E = OFF bit + LEN bit set)
test "frame: STREAM frame parsed", ->
  payload = "world"
  -- 0x0E: STREAM with offset(0x04) and length(0x02) bits set
  data = "\x0E" .. encode_varint(1) .. encode_varint(0) .. encode_varint(#payload) .. payload
  f, _ = parse_frame data, 1
  assert f.type == 0x0E and f.name == "STREAM"
  assert f.id == 1
  assert f.data == payload

-- RESET_STREAM (0x04)
test "frame: RESET_STREAM parsed", ->
  data = "\x04" .. encode_varint(3) .. encode_varint(0) .. encode_varint(100)
  f, _ = parse_frame data, 1
  assert f.type == 0x04 and f.name == "RESET_STREAM"
  assert f.stream_id == 3 and f.final_size == 100

-- STOP_SENDING (0x05)
test "frame: STOP_SENDING parsed", ->
  data = "\x05" .. encode_varint(7) .. encode_varint(42)
  f, _ = parse_frame data, 1
  assert f.type == 0x05 and f.name == "STOP_SENDING"
  assert f.stream_id == 7 and f.app_error_code == 42

-- MAX_DATA (0x10)
test "frame: MAX_DATA parsed", ->
  data = "\x10" .. encode_varint(1000)
  f, _ = parse_frame data, 1
  assert f.type == 0x10 and f.name == "MAX_DATA"
  assert f.maximum_data == 1000

-- MAX_STREAM_DATA (0x11)
test "frame: MAX_STREAM_DATA parsed", ->
  data = "\x11" .. encode_varint(2) .. encode_varint(2000)
  f, _ = parse_frame data, 1
  assert f.type == 0x11 and f.name == "MAX_STREAM_DATA"
  assert f.stream_id == 2 and f.maximum_stream_data == 2000

-- MAX_STREAMS bidi (0x12)
test "frame: MAX_STREAMS_BIDI parsed", ->
  data = "\x12" .. encode_varint(10)
  f, _ = parse_frame data, 1
  assert f.type == 0x12 and f.name == "MAX_STREAMS_BIDI"
  assert f.maximum_streams == 10

-- DATA_BLOCKED (0x14)
test "frame: DATA_BLOCKED parsed", ->
  data = "\x14" .. encode_varint(500)
  f, _ = parse_frame data, 1
  assert f.type == 0x14 and f.name == "DATA_BLOCKED"
  assert f.maximum_data == 500

-- NEW_CONNECTION_ID (0x18)
test "frame: NEW_CONNECTION_ID parsed", ->
  cid = "\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"
  rst = string.rep("\x00", 16)  -- 16-byte stateless reset token
  data = "\x18" .. encode_varint(1) .. encode_varint(0) .. "\x08" .. cid .. rst
  f, _ = parse_frame data, 1
  assert f.type == 0x18 and f.name == "NEW_CONNECTION_ID"
  assert f.sequence_number == 1
  assert f.connection_id == cid

-- RETIRE_CONNECTION_ID (0x19)
test "frame: RETIRE_CONNECTION_ID parsed", ->
  data = "\x19" .. encode_varint(5)
  f, _ = parse_frame data, 1
  assert f.type == 0x19 and f.name == "RETIRE_CONNECTION_ID"
  assert f.sequence_number == 5

-- PATH_CHALLENGE (0x1a) — 8 bytes of data
test "frame: PATH_CHALLENGE parsed", ->
  data = "\x1a" .. string.rep("\xAB", 8)
  f, _ = parse_frame data, 1
  assert f.type == 0x1a and f.name == "PATH_CHALLENGE"
  assert #f.data == 8

-- PATH_RESPONSE (0x1b)
test "frame: PATH_RESPONSE parsed", ->
  data = "\x1b" .. string.rep("\xCD", 8)
  f, _ = parse_frame data, 1
  assert f.type == 0x1b and f.name == "PATH_RESPONSE"

-- CONNECTION_CLOSE (0x1c)
test "frame: CONNECTION_CLOSE parsed", ->
  reason = "test error"
  data = "\x1c" .. encode_varint(0) .. encode_varint(0) .. encode_varint(#reason) .. reason
  f, _ = parse_frame data, 1
  assert f.type == 0x1c and f.name == "CONNECTION_CLOSE"
  assert f.reason_phrase == reason

-- HANDSHAKE_DONE (0x1e) — no fields
test "frame: HANDSHAKE_DONE parsed", ->
  f, _ = parse_frame "\x1e", 1
  assert f.type == 0x1e and f.name == "HANDSHAKE_DONE"

test "frame: CRYPTO truncated payload returns nil", ->
  data = "\x06\x00\x05\xaa" -- offset=0, len=5, only 1 byte payload
  f, _, err = parse_frame data, 1
  assert f == nil, "expected parse failure"
  assert err and err\match("CRYPTO"), "expected CRYPTO error, got #{err}"

test "frame: PATH_CHALLENGE truncated returns nil", ->
  f, _, err = parse_frame "\x1a\xaa", 1
  assert f == nil, "expected parse failure"
  assert err and err\match("PATH_CHALLENGE"), "expected PATH_CHALLENGE error, got #{err}"

-- iter_frames: two frames
test "frame: iter_frames over two frames", ->
  data = "\x01\x01"  -- PING, PING
  count = 0
  for f in iter_frames data
    count += 1
  assert count == 2, "expected 2 frames, got #{count}"

-- validate_frames
test "frame: validate_frames succeeds on valid data", ->
  data = "\x01\x01"
  ok, msg = validate_frames data
  assert ok == true, "expected valid, got: #{msg}"

test "frame: validate_frames fails on malformed data", ->
  data = "\x06\x00\x05\xaa"
  ok, msg = validate_frames data
  assert ok == false, "expected invalid data"
  assert msg and msg\match("CRYPTO"), "expected CRYPTO validation error, got #{msg}"

-- UNKNOWN frame type advances offset
test "frame: UNKNOWN frame does not get stuck", ->
  -- 0x30 is CONNECTION_CLOSE (wait, let me check)
  -- Actually the remaining frames we haven't mapped:
  -- Let's use a reserved/unknown type like 0x20
  -- encode_varint(0x20) = 0x20 (< 64, 1-byte)
  data = "\x20\x01"  -- unknown type, then PING
  f1, off1 = parse_frame data, 1
  assert f1.name == "UNKNOWN", "expected UNKNOWN, got #{f1.name}"
  f2, off2 = parse_frame data, off1
  assert f2.name == "PING", "expected PING after UNKNOWN, got #{f2.name}"

util.summary "frames"
