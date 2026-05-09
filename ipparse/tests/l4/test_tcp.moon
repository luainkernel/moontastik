util = require"ipparse.lib.util"
{:test} = util
tcp = require"ipparse.l4.tcp"

mk_tcp = (opts={}) ->
  tcp.new {
    spt: opts.spt or 1234
    dpt: opts.dpt or 80
    seq_n: opts.seq_n or 0
    ack_n: opts.ack_n or 0
    header_len: 0x50
    window: opts.window or 65535
    checksum: 0
    urg_ptr: 0
    options: ""
    syn: opts.syn
    ack: opts.ack
    fin: opts.fin
    rst: opts.rst
    psh: opts.psh
  }

test "parse extracts spt and dpt", ->
  t = mk_tcp {spt: 4321, dpt: 80}
  raw = tostring t
  parsed, _ = tcp.parse raw, 1
  assert parsed.spt == 4321, "spt should be 4321, got #{parsed.spt}"
  assert parsed.dpt == 80, "dpt should be 80, got #{parsed.dpt}"

test "parse extracts seq_n", ->
  t = mk_tcp {seq_n: 0xdeadbeef}
  -- set seq_n after construction since mk_tcp defaults to 0
  t2 = tcp.new {
    spt: 1234, dpt: 80, seq_n: 0xdeadbeef, ack_n: 0
    header_len: 0x50, window: 65535, checksum: 0, urg_ptr: 0
    options: ""
  }
  raw = tostring t2
  parsed, _ = tcp.parse raw, 1
  assert parsed.seq_n == 0xdeadbeef, "seq_n should be 0xdeadbeef, got #{parsed.seq_n}"

test "SYN flag set via new", ->
  t = mk_tcp {syn: true}
  assert t.SYN == true, "SYN should be true"

test "ACK flag set via new", ->
  t = mk_tcp {ack: true}
  assert t.ACK == true, "ACK should be true"

test "FIN flag set via new", ->
  t = mk_tcp {fin: true}
  assert t.FIN == true, "FIN should be true"

test "RST flag set via new", ->
  t = mk_tcp {rst: true}
  assert t.RST == true, "RST should be true"

test "PSH flag set via new", ->
  t = mk_tcp {psh: true}
  assert t.PSH == true, "PSH should be true"

test "no flags set when none provided", ->
  t = mk_tcp {}
  assert t.SYN == false, "SYN should be false"
  assert t.ACK == false, "ACK should be false"
  assert t.FIN == false, "FIN should be false"

test "SYN flag settable via __newindex", ->
  t = mk_tcp {}
  t.SYN = true
  assert t.SYN == true, "SYN should be true after setting"

test "SYN flag clearable via __newindex", ->
  t = mk_tcp {syn: true}
  t.SYN = false
  assert t.SYN == false, "SYN should be false after clearing"

test "flags table: SYN == 0x02", ->
  assert tcp.flags.SYN == 0x02, "SYN flag value should be 0x02"
  assert tcp.flags.ACK == 0x10, "ACK flag value should be 0x10"
  assert tcp.flags.FIN == 0x01, "FIN flag value should be 0x01"

test "flags bidirectional reverse lookup", ->
  assert tcp.flags[0x02] == "SYN", "reverse lookup 0x02 should be SYN"

test "data_off is off+20 for standard header", ->
  t = mk_tcp {}
  raw = tostring t
  parsed, _ = tcp.parse raw, 1
  assert parsed.data_off == 21, "data_off should be 21 (1+20), got #{parsed.data_off}"

test "round-trip: new -> tostring -> parse", ->
  t = mk_tcp {spt: 9999, dpt: 443, syn: true}
  raw = tostring t
  parsed, _ = tcp.parse raw, 1
  assert parsed.spt == 9999, "round-trip spt mismatch"
  assert parsed.dpt == 443, "round-trip dpt mismatch"
  assert parsed.SYN == true, "round-trip SYN flag mismatch"

test "options empty in standard header", ->
  t = mk_tcp {}
  raw = tostring t
  parsed, _ = tcp.parse raw, 1
  assert parsed.options == "", "options should be empty string, got '#{parsed.options}'"
util.summary "l4/tcp"
