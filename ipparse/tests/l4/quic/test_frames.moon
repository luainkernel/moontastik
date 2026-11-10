--
-- SPDX-FileCopyrightText: (c) 2024-2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- tests/l4/quic/test_frames.moon
-- Tests for QUIC frame parsing

util = require "ipparse.lib.util"
{:test} = util
{:parse_frame, :iter_frames, :validate_frames, :encode_varint, :parse_varint} = require "ipparse.l4.quic.frames"

-- PADDING frame (0x00)
test "frame: PADDING parsed", ->
  f, off = parse_frame "\000", 1
  assert f.type == 0x00 and f.name == "PADDING", "expected PADDING"

-- PING frame (0x01)
test "frame: PING parsed", ->
  f, off = parse_frame "\001", 1
  assert f.type == 0x01 and f.name == "PING", "expected PING"

-- ACK frame (0x02) — minimal: largest_acked=0, delay=0, count=0, first=0
test "frame: ACK minimal parsed", ->
  data = "\002\000\000\000\000"  -- type + 4 VarInts of value 0
  f, _ = parse_frame data, 1
  assert f.type == 0x02 and f.name == "ACK"
  assert f.largest_acked == 0

-- CRYPTO frame (0x06)
test "frame: CRYPTO frame parsed", ->
  payload = "hello"
  -- type(0x06) + offset(0) + length(5) + data
  data = "\006" .. encode_varint(0) .. encode_varint(#payload) .. payload
  f, _ = parse_frame data, 1
  assert f.type == 0x06 and f.name == "CRYPTO"
  assert f.data == payload, "crypto data mismatch"
  assert f.length == 5

-- STREAM frame (0x0E = OFF bit + LEN bit set)
test "frame: STREAM frame parsed", ->
  payload = "world"
  -- 0x0E: STREAM with offset(0x04) and length(0x02) bits set
  data = "\014" .. encode_varint(1) .. encode_varint(0) .. encode_varint(#payload) .. payload
  f, _ = parse_frame data, 1
  assert f.type == 0x0E and f.name == "STREAM"
  assert f.id == 1
  assert f.data == payload

-- RESET_STREAM (0x04)
test "frame: RESET_STREAM parsed", ->
  data = "\004" .. encode_varint(3) .. encode_varint(0) .. encode_varint(100)
  f, _ = parse_frame data, 1
  assert f.type == 0x04 and f.name == "RESET_STREAM"
  assert f.stream_id == 3 and f.final_size == 100

-- STOP_SENDING (0x05)
test "frame: STOP_SENDING parsed", ->
  data = "\005" .. encode_varint(7) .. encode_varint(42)
  f, _ = parse_frame data, 1
  assert f.type == 0x05 and f.name == "STOP_SENDING"
  assert f.stream_id == 7 and f.app_error_code == 42

-- MAX_DATA (0x10)
test "frame: MAX_DATA parsed", ->
  data = "\016" .. encode_varint(1000)
  f, _ = parse_frame data, 1
  assert f.type == 0x10 and f.name == "MAX_DATA"
  assert f.maximum_data == 1000

-- MAX_STREAM_DATA (0x11)
test "frame: MAX_STREAM_DATA parsed", ->
  data = "\017" .. encode_varint(2) .. encode_varint(2000)
  f, _ = parse_frame data, 1
  assert f.type == 0x11 and f.name == "MAX_STREAM_DATA"
  assert f.stream_id == 2 and f.maximum_stream_data == 2000

-- MAX_STREAMS bidi (0x12)
test "frame: MAX_STREAMS_BIDI parsed", ->
  data = "\018" .. encode_varint(10)
  f, _ = parse_frame data, 1
  assert f.type == 0x12 and f.name == "MAX_STREAMS_BIDI"
  assert f.maximum_streams == 10

-- DATA_BLOCKED (0x14)
test "frame: DATA_BLOCKED parsed", ->
  data = "\020" .. encode_varint(500)
  f, _ = parse_frame data, 1
  assert f.type == 0x14 and f.name == "DATA_BLOCKED"
  assert f.maximum_data == 500

-- NEW_CONNECTION_ID (0x18)
test "frame: NEW_CONNECTION_ID parsed", ->
  cid = "\170\187\204\221\238\255\017\034"
  rst = string.rep("\000", 16)  -- 16-byte stateless reset token
  data = "\024" .. encode_varint(1) .. encode_varint(0) .. "\008" .. cid .. rst
  f, _ = parse_frame data, 1
  assert f.type == 0x18 and f.name == "NEW_CONNECTION_ID"
  assert f.sequence_number == 1
  assert f.connection_id == cid

-- RETIRE_CONNECTION_ID (0x19)
test "frame: RETIRE_CONNECTION_ID parsed", ->
  data = "\025" .. encode_varint(5)
  f, _ = parse_frame data, 1
  assert f.type == 0x19 and f.name == "RETIRE_CONNECTION_ID"
  assert f.sequence_number == 5

-- PATH_CHALLENGE (0x1a) — 8 bytes of data
test "frame: PATH_CHALLENGE parsed", ->
  data = "\026" .. string.rep("\171", 8)
  f, _ = parse_frame data, 1
  assert f.type == 0x1a and f.name == "PATH_CHALLENGE"
  assert #f.data == 8

-- PATH_RESPONSE (0x1b)
test "frame: PATH_RESPONSE parsed", ->
  data = "\027" .. string.rep("\205", 8)
  f, _ = parse_frame data, 1
  assert f.type == 0x1b and f.name == "PATH_RESPONSE"

-- CONNECTION_CLOSE (0x1c)
test "frame: CONNECTION_CLOSE parsed", ->
  reason = "test error"
  data = "\028" .. encode_varint(0) .. encode_varint(0) .. encode_varint(#reason) .. reason
  f, _ = parse_frame data, 1
  assert f.type == 0x1c and f.name == "CONNECTION_CLOSE"
  assert f.reason_phrase == reason

-- HANDSHAKE_DONE (0x1e) — no fields
test "frame: HANDSHAKE_DONE parsed", ->
  f, _ = parse_frame "\030", 1
  assert f.type == 0x1e and f.name == "HANDSHAKE_DONE"

test "frame: CRYPTO truncated payload returns nil", ->
  data = "\006\000\005\170" -- offset=0, len=5, only 1 byte payload
  f, _, err = parse_frame data, 1
  assert f == nil, "expected parse failure"
  assert err and err\match("CRYPTO"), "expected CRYPTO error, got #{err}"

test "frame: PATH_CHALLENGE truncated returns nil", ->
  f, _, err = parse_frame "\026\170", 1
  assert f == nil, "expected parse failure"
  assert err and err\match("PATH_CHALLENGE"), "expected PATH_CHALLENGE error, got #{err}"

-- iter_frames: two frames
test "frame: iter_frames over two frames", ->
  data = "\001\001"  -- PING, PING
  count = 0
  for f in iter_frames data
    count += 1
  assert count == 2, "expected 2 frames, got #{count}"

-- validate_frames
test "frame: validate_frames succeeds on valid data", ->
  data = "\001\001"
  ok, msg = validate_frames data
  assert ok == true, "expected valid, got: #{msg}"

test "frame: validate_frames fails on malformed data", ->
  data = "\006\000\005\170"
  ok, msg = validate_frames data
  assert ok == false, "expected invalid data"
  assert msg and msg\match("CRYPTO"), "expected CRYPTO validation error, got #{msg}"

-- UNKNOWN frame type advances offset
test "frame: UNKNOWN frame does not get stuck", ->
  -- 0x30 is CONNECTION_CLOSE (wait, let me check)
  -- Actually the remaining frames we haven't mapped:
  -- Let's use a reserved/unknown type like 0x20
  -- encode_varint(0x20) = 0x20 (< 64, 1-byte)
  data = "\032\001"  -- unknown type, then PING
  f1, off1 = parse_frame data, 1
  assert f1.name == "UNKNOWN", "expected UNKNOWN, got #{f1.name}"
  f2, off2 = parse_frame data, off1
  assert f2.name == "PING", "expected PING after UNKNOWN, got #{f2.name}"

-- Dispatch: type-dependent parsers receive their frame type
test "frame: type-dependent parsers dispatch correctly", ->
  -- ACK_ECN (0x03): 4 base varints + 3 ECN counts
  data = "\003\000\000\000\000\000\000\000"
  f, _ = parse_frame data, 1
  assert f.type == 0x03 and f.name == "ACK_ECN", "expected ACK_ECN"

  -- MAX_STREAMS_UNI (0x13)
  f, _ = parse_frame "\019\001", 1
  assert f.type == 0x13 and f.name == "MAX_STREAMS_UNI", "expected MAX_STREAMS_UNI"

  -- STREAMS_BLOCKED_BIDI (0x16) / UNI (0x17)
  f, _ = parse_frame "\022\001", 1
  assert f.type == 0x16 and f.name == "STREAMS_BLOCKED_BIDI", "expected STREAMS_BLOCKED_BIDI"
  f, _ = parse_frame "\023\001", 1
  assert f.type == 0x17 and f.name == "STREAMS_BLOCKED_UNI", "expected STREAMS_BLOCKED_UNI"

  -- CONNECTION_CLOSE_APP (0x1d): error_code, reason_length (no frame_type field)
  f, _ = parse_frame "\029\000\000", 1
  assert f.type == 0x1d and f.name == "CONNECTION_CLOSE_APP", "expected CONNECTION_CLOSE_APP"

  -- STREAM types 0x08..0x0f all dispatch to parse_stream_frame
  for t = 0x08, 0x0f
    f, _ = parse_frame (string.char(t) .. "\001\000\000\000"), 1
    assert f and f.type == t and f.name == "STREAM", "expected STREAM for type #{t}"

-- PADDING runs are coalesced into a single frame (RFC 9000 §12.1: PADDING
-- frames may be arbitrarily many consecutive zero bytes).
test "frame: PADDING run coalesced into one frame", ->
  data = string.rep("\000", 1000)
  count = 0
  f = nil
  for frame in iter_frames data
    count += 1
    f = frame
  assert count == 1, "expected 1 PADDING frame, got #{count}"
  assert f.type == 0x00 and f.name == "PADDING", "expected PADDING"
  assert f.length == 1000, "expected length 1000, got #{f.length}"

test "frame: PADDING run interrupted by other frames", ->
  data = "\000\000\001\000"  -- PADDING(2), PING, PADDING(1)
  frames = {}
  for frame in iter_frames data
    frames[#frames + 1] = frame
  assert #frames == 3, "expected 3 frames, got #{#frames}"
  assert frames[1].name == "PADDING" and frames[1].length == 2, "expected PADDING(2)"
  assert frames[2].name == "PING", "expected PING"
  assert frames[3].name == "PADDING" and frames[3].length == 1, "expected PADDING(1)"

test "frame: validate_frames counts a PADDING run once", ->
  ok, msg = validate_frames string.rep("\000", 1000)
  assert ok == true, "expected valid, got: #{msg}"
  assert msg\match("1 frames validated"), "expected 1 frame, got: #{msg}"

-- encode_varint covers all four size classes and parse_varint reads them back.
test "frame: encode_varint four sizes round-trip", ->
  for value in *{63, 16383, 1073741823, 1073741824}
    enc = encode_varint value
    assert #enc >= 1 and #enc <= 8, "bad length #{#enc} for #{value}"
    dec, off = parse_varint enc, 1
    assert dec == value, "expected #{value}, got #{dec}"
    assert off == #enc + 1, "offset should be past the varint"

test "frame: parse_varint truncated inputs return nil", ->
  cases = {
    {"", 1}                    -- offset past data
    {"\064", 1}                -- 2-byte varint, no second byte
    {"\128\000\000", 1}        -- 4-byte varint, only 3 bytes
    {"\192\000\000\000\000\000\000", 1} -- 8-byte varint, only 7 bytes
  }
  for c in *cases
    v, off = parse_varint c[1], c[2]
    assert v == nil, "expected nil for truncated varint"
    assert off == c[2], "offset should be unchanged"

test "frame: parse_frame on empty input returns nil", ->
  f, off = parse_frame "", 1
  assert f == nil and off == 1, "expected nil at offset 1"

test "frame: parse_frame truncated frame type varint", ->
  f, _, err = parse_frame "\064", 1
  assert f == nil, "expected nil frame"
  assert err and err\match("truncated frame type"), "expected truncated type error, got #{err}"

test "frame: ACK with one range parses gap and length", ->
  data = "\002\000\000\001\000\000\005"
  f, off = parse_frame data, 1
  assert f and f.name == "ACK", "expected ACK"
  assert f.ack_range_count == 1, "expected 1 range"
  assert #f.ack_ranges == 1, "expected one parsed range"
  assert f.ack_ranges[1].gap == 0 and f.ack_ranges[1].length == 5, "range mismatch"
  assert off == #data + 1, "offset should be past the frame"

test "frame: ACK truncated fields return nil", ->
  cases = {
    {"\002"}                     -- missing ack_delay, range_count, first_range
    {"\002\000"}                 -- missing range_count, first_range
    {"\002\000\000"}             -- missing first_range
    {"\002\000\000\000\000"}   -- all four varints present
  }
  -- The first three are truncated; the fourth has all four varints.
  for i = 1, 3
    f, _, err = parse_frame cases[i][1], 1
    assert f == nil and err, "expected truncation for case #{i}"
  f = parse_frame cases[4][1], 1
  assert f and f.name == "ACK", "four zero varints should parse"

test "frame: ACK range count too large rejected", ->
  f, _, err = parse_frame "\002\000\000\005\000", 1
  assert f == nil, "expected nil frame"
  assert err and err\match("ack_range_count"), "expected range count error, got #{err}"

test "frame: ACK_ECN truncated ECN counters return nil", ->
  base = "\003\000\000\000\000"
  for i = 1, 3
    f, _, err = parse_frame base .. string.rep("\000", i - 1), 1
    assert f == nil and err, "expected truncation for ECN counter #{i}"

test "frame: RESET_STREAM truncated fields return nil", ->
  for data in *{"\004", "\004\001", "\004\001\001"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected truncation for RESET_STREAM"

test "frame: STOP_SENDING truncated fields return nil", ->
  for data in *{"\005", "\005\001"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected truncation for STOP_SENDING"

test "frame: CRYPTO truncated offset and length return nil", ->
  for data in *{"\006", "\006\000"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected truncation for CRYPTO"

test "frame: NEW_TOKEN parsed", ->
  token = "tok123"
  data = "\007" .. encode_varint(#token) .. token
  f, off = parse_frame data, 1
  assert f and f.name == "NEW_TOKEN", "expected NEW_TOKEN"
  assert f.token == token and f.token_length == #token, "token mismatch"
  assert off == #data + 1, "offset should be past the frame"

test "frame: NEW_TOKEN truncated length and payload return nil", ->
  f, _, err = parse_frame "\007", 1
  assert f == nil and err, "expected truncated length error"
  f, _, err = parse_frame "\007\005ab", 1
  assert f == nil, "expected nil on short payload"
  assert err and err\match("NEW_TOKEN"), "expected NEW_TOKEN error, got #{err}"

test "frame: STREAM variants without offset/length and with FIN", ->
  -- 0x08: no offset, no length, data is the rest
  f, _ = parse_frame "\008\001abc", 1
  assert f and f.name == "STREAM", "expected STREAM"
  assert f.offset == 0 and f.data == "abc" and f.fin == false, "0x08 mismatch"
  -- 0x09: FIN added
  f, _ = parse_frame "\009\001abc", 1
  assert f.fin == true, "0x09 should set fin"
  -- 0x0a: length, no offset
  f, _ = parse_frame ("\010\001\003abc"), 1
  assert f.offset == 0 and f.length == 3 and f.data == "abc", "0x0a mismatch"
  -- 0x0c: offset, no length
  f, _ = parse_frame ("\012\001\007abc"), 1
  assert f.offset == 7 and f.data == "abc", "0x0c mismatch"
  -- 0x0f: offset, length, fin
  f, _ = parse_frame ("\015\001\007\003abc"), 1
  assert f.offset == 7 and f.length == 3 and f.fin == true, "0x0f mismatch"

test "frame: STREAM truncated fields and payload return nil", ->
  for data in *{"\014", "\014\001", "\014\001\000", "\014\001\000\005ab"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected STREAM truncation"

test "frame: MAX_DATA truncated returns nil", ->
  f, _, err = parse_frame "\016", 1
  assert f == nil and err, "expected MAX_DATA truncation"

test "frame: MAX_STREAM_DATA truncated fields return nil", ->
  for data in *{"\017", "\017\001"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected MAX_STREAM_DATA truncation"

test "frame: MAX_STREAMS truncated returns nil", ->
  for t in *{"\018", "\019"}
    f, _, err = parse_frame t, 1
    assert f == nil and err, "expected MAX_STREAMS truncation"

test "frame: DATA_BLOCKED truncated returns nil", ->
  f, _, err = parse_frame "\020", 1
  assert f == nil and err, "expected DATA_BLOCKED truncation"

test "frame: STREAM_DATA_BLOCKED parsed and truncated", ->
  data = "\021" .. encode_varint(4) .. encode_varint(900)
  f, off = parse_frame data, 1
  assert f and f.name == "STREAM_DATA_BLOCKED", "expected STREAM_DATA_BLOCKED"
  assert f.stream_id == 4 and f.maximum_stream_data == 900, "fields mismatch"
  assert off == #data + 1, "offset should be past the frame"
  for bad in *{"\021", "\021\004"}
    f, _, err = parse_frame bad, 1
    assert f == nil and err, "expected STREAM_DATA_BLOCKED truncation"

test "frame: STREAMS_BLOCKED truncated returns nil", ->
  for t in *{"\022", "\023"}
    f, _, err = parse_frame t, 1
    assert f == nil and err, "expected STREAMS_BLOCKED truncation"

test "frame: NEW_CONNECTION_ID truncated fields return nil", ->
  cases = {
    "\024"                              -- missing retire_prior_to
    "\024\001"                          -- missing cid_length
    "\024\001\000\004\001\002"          -- cid longer than remaining
    "\024\001\000\001\170"              -- missing 16-byte reset token
  }
  for i = 1, #cases
    f, _, err = parse_frame cases[i], 1
    assert f == nil and err, "expected NEW_CONNECTION_ID truncation for case #{i}"

test "frame: RETIRE_CONNECTION_ID truncated returns nil", ->
  f, _, err = parse_frame "\025", 1
  assert f == nil and err, "expected RETIRE_CONNECTION_ID truncation"

test "frame: PATH_RESPONSE truncated returns nil", ->
  f, _, err = parse_frame "\027\170", 1
  assert f == nil, "expected nil frame"
  assert err and err\match("PATH_RESPONSE"), "expected PATH_RESPONSE error, got #{err}"

test "frame: CONNECTION_CLOSE truncated fields return nil", ->
  -- 0x1c needs error_code, frame_type, reason_length
  for data in *{"\028", "\028\000", "\028\000\000"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected CONNECTION_CLOSE truncation"
  -- reason length beyond frame data
  f, _, err = parse_frame "\028\000\000\005ab", 1
  assert f == nil, "expected nil on short reason"
  assert err and err\match("CONNECTION_CLOSE"), "expected CONNECTION_CLOSE error, got #{err}"
  -- 0x1d needs error_code and reason_length only
  for data in *{"\029", "\029\000"}
    f, _, err = parse_frame data, 1
    assert f == nil and err, "expected CONNECTION_CLOSE_APP truncation"

test "frame: iter_frames stops on a malformed frame", ->
  count = 0
  for f in iter_frames "\006"
    count += 1
  assert count == 0, "expected no frames from malformed data, got #{count}"

util.summary "frames"
