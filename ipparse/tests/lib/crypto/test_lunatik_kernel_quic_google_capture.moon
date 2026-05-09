-- tests/lib/crypto/test_lunatik_kernel_quic_google_capture.moon
-- Lunatik kernel capture-based test: full L2 -> SNI parsing on quic_google.pcapng.

unpack: su = require "ipparse.lib.pack_compat"
{:band} = require "ipparse.lib.bit_compat"
eth_mod = require "ipparse.l2.ethernet"
ip_mod = require "ipparse.l3.ip"
udp_mod = require "ipparse.l4.udp"
quic_mod = require "ipparse.l4.quic"
keys_mod = require "ipparse.l4.quic.v1.keys"
prot_mod = require "ipparse.l4.quic.v1.protection"
frames_mod = require "ipparse.l4.quic.frames"
backend = require "ipparse.lib.crypto.backend.lunatik"

bin2hex = (s) ->
  return s\gsub ".", (c) -> string.format "%02x", string.byte c

tests_passed = 0
tests_failed = 0

assert_test = (name, fn) ->
  ok, err = pcall fn
  if ok
    tests_passed += 1
    print "PASS\tlunatik: #{name}"
  else
    tests_failed += 1
    print "FAIL\tlunatik: #{name}\t#{err}"
    error err

EXPECTED = {
  dst_mac: "f2198cc26bb3"
  src_mac: "f2e9008a2acc"
  src_ip:  "3ffa:e7fe:4375:16ed:e28f:4cff:fec8:91fa"
  dst_ip:  "2485:ec87:7655:20de:0:0:0:8b"
  udp_spt: 35336
  udp_dpt: 443
  sni: "google.com"
}

reassemble_crypto = (plaintext) ->
  chunks = {}
  for f in frames_mod.iter_frames plaintext
    continue unless f and f.name == "CRYPTO" and f.data
    base = f.offset or 0
    chunks[base] = f.data unless chunks[base]
  offsets = [off for off, _ in pairs chunks]
  return "" if #offsets == 0
  table.sort offsets
  out = {}
  expected = 0
  for off in *offsets
    chunk = chunks[off]
    clen = #chunk
    chunk_end = off + clen - 1
    continue if chunk_end < expected
    break if off > expected
    start_idx = expected > off and (expected - off + 1) or 1
    out[#out + 1] = chunk\sub start_idx
    expected = chunk_end + 1
  table.concat out

sni_from_tls = (tls_data) ->
  return nil if #tls_data < 5
  off = 1
  while off + 3 <= #tls_data
    msg_type = su "B", tls_data, off
    b_hi = su "B", tls_data, off + 1
    b_lo = su ">H", tls_data, off + 2
    msg_len = b_hi * 65536 + b_lo
    body_off = off + 4
    break if body_off + msg_len - 1 > #tls_data
    if msg_type == 0x01
      body = tls_data\sub body_off, body_off + msg_len - 1
      p = 1
      break if #body < 39
      p += 2 -- client_version
      p += 32 -- random
      sid_len = su "B", body, p
      p += 1 + sid_len
      break if p + 1 > #body
      cs_len = su ">H", body, p
      p += 2 + cs_len
      break if p > #body
      comp_len = su "B", body, p
      p += 1 + comp_len
      break if p + 1 > #body
      ext_len = su ">H", body, p
      p += 2
      ext_end = p + ext_len - 1
      break if ext_end > #body
      while p + 3 <= ext_end
        ext_type = su ">H", body, p
        ext_data_len = su ">H", body, p + 2
        p += 4
        break if p + ext_data_len - 1 > ext_end
        if ext_type == 0x0000 and ext_data_len >= 5
          sn_off = p
          sn_list_len = su ">H", body, sn_off
          sn_off += 2
          sn_end = p + ext_data_len - 1
          if sn_off + sn_list_len - 1 <= sn_end
            while sn_off + 2 <= sn_end
              name_type = su "B", body, sn_off
              name_len = su ">H", body, sn_off + 1
              sn_off += 3
              break if sn_off + name_len - 1 > sn_end
              if name_type == 0
                return body\sub sn_off, sn_off + name_len - 1
              sn_off += name_len
        p += ext_data_len
    off = body_off + msg_len
  nil

append_crypto_chunks = (chunks, plaintext) ->
  for f in frames_mod.iter_frames plaintext
    continue unless f and f.name == "CRYPTO" and f.data
    base = f.offset or 0
    prev = chunks[base]
    chunks[base] = f.data unless prev

crypto_stream_from_chunks = (chunks) ->
  offsets = [off for off, _ in pairs chunks]
  return "" if #offsets == 0
  table.sort offsets
  out = {}
  expected = 0
  for off in *offsets
    chunk = chunks[off]
    chunk_end = off + #chunk - 1
    continue if chunk_end < expected
    break if off > expected
    start_idx = expected > off and (expected - off + 1) or 1
    out[#out + 1] = chunk\sub start_idx
    expected = chunk_end + 1
  table.concat out

bruteforce_decrypt_initial = (quic_packet, q_pkt, key, iv, expected_pn) ->
  pn_off = q_pkt.pn_off
  prefix = (pn_off > 2 and quic_packet\sub(2, pn_off - 1) or "")
  protected_first = string.byte quic_packet, 1
  first_top = band protected_first, 0xF0

  try_full_pn = (first_byte, pn_len, payload_off, full_pn) ->
    return nil if full_pn < 0
    pn_space = 1
    for _ = 1, pn_len
      pn_space *= 256
    truncated = full_pn % pn_space
    pn_bytes = {}
    i = pn_len
    while i >= 1
      b = truncated % 256
      pn_bytes[i] = string.char b
      truncated = (truncated - b) / 256
      i -= 1
    aad = string.char(first_byte) .. prefix .. table.concat(pn_bytes)
    plaintext, dec_err = prot_mod.decrypt_payload quic_packet, payload_off, key, iv, full_pn, aad, backend
    return nil unless plaintext
    {
      :plaintext
      pn: full_pn
    }

  reserved_bits = 0
  while reserved_bits <= 3
    pn_len = 1
    while pn_len <= 4
      first_nibble = reserved_bits * 4 + (pn_len - 1)
      first_byte = first_top + first_nibble
      payload_off = pn_off + pn_len
      if payload_off <= #quic_packet
        max_delta = pn_len == 1 and 255 or 4096
        delta = 0
        while delta <= max_delta
          fwd = expected_pn + delta
          dec = try_full_pn first_byte, pn_len, payload_off, fwd
          return dec if dec
          if delta > 0 and expected_pn >= delta
            back = expected_pn - delta
            dec = try_full_pn first_byte, pn_len, payload_off, back
            return dec if dec
          delta += 1
      pn_len += 1
    reserved_bits += 1

  nil

resolve_capture_path = ->
  candidates = {
    "/lib/modules/lua/ipparse/quic_google.pcapng"
    "ipparse/quic_google.pcapng"
    "quic_google.pcapng"
  }

  for path in *candidates
    f = io.open path, "rb"
    if f
      f\close!
      return path

  error "quic_google.pcapng not found (tried: #{table.concat candidates, ', '})"

for_each_epb = (capture_path, cb) ->
  file = io.open capture_path, "rb"
  error "Could not open file: #{capture_path}" unless file

  endian = nil
  epb_count = 0

  while true
    hdr = file\read 8
    break unless hdr and #hdr == 8

    block_type_le = su "<I4", hdr, 1
    block_type_be = su ">I4", hdr, 1
    shb = (block_type_le == 0x0A0D0D0A) or (block_type_be == 0x0A0D0D0A)

    if shb
      bom_bytes = file\read 4
      break unless bom_bytes and #bom_bytes == 4

      bom_le = su "<I4", bom_bytes, 1
      bom_be = su ">I4", bom_bytes, 1
      if bom_le == 0x1A2B3C4D
        endian = "<"
      elseif bom_be == 0x1A2B3C4D
        endian = ">"
      else
        error "Invalid SHB byte-order magic in #{capture_path}"

      block_len = su "#{endian}I4", hdr, 5
      break if block_len < 12

      rest = block_len - 12
      if rest > 0
        chunk = file\read rest
        break unless chunk and #chunk == rest
    else
      error "PCAPNG section header missing before first non-SHB block" unless endian

      block_len = su "#{endian}I4", hdr, 5
      break if block_len < 12

      payload_len = block_len - 8
      payload = file\read payload_len
      break unless payload and #payload == payload_len

      block_type = su "#{endian}I4", hdr, 1
      if block_type == 0x00000006
        epb_count += 1
        interface_id, timestamp_high, timestamp_low, captured_len, original_len = su "#{endian}I4I4I4I4I4", payload, 1
        packet_start = 21
        packet_end = packet_start + captured_len - 1
        if packet_end <= #payload
          should_stop = cb payload, packet_start, packet_end, epb_count
          break if should_stop

  file\close!
  epb_count

scan_first_initial = (capture_path) ->
  first = nil
  initial_dcid = nil
  epb_count = for_each_epb capture_path, (payload, packet_start, packet_end, epb_idx) ->
    e, l3_off = eth_mod.parse payload, packet_start
    return false unless e

    ip_pkt, l4_off = ip_mod.parse payload, l3_off
    return false unless ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP

    udp_dgram, l7_off = udp_mod.parse payload, l4_off
    return false unless udp_dgram

    q, _ = quic_mod.parse payload, l7_off
    return false unless q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0

    first = {
      :e
      ip_pkt: ip_pkt
      udp_dgram: udp_dgram
      q: q
      epb_idx: epb_idx
    }
    initial_dcid = q.dst_connection_id
    true

  assert first ~= nil, "no QUIC Initial packet found in #{capture_path}"
  {
    :first
    :initial_dcid
    :epb_count
  }

extract_sni = (capture_path, initial_dcid) ->
  print "INFO\tlunatik: extract_sni stage=derive_initial_secrets"
  ok_secret, client_secret, server_secret_or_err = pcall keys_mod.derive_initial_secrets, initial_dcid
  assert ok_secret, "derive_initial_secrets_failed: #{server_secret_or_err}"
  print "INFO\tlunatik: extract_sni stage=derive_keys"
  key, iv, _ = keys_mod.derive_keys client_secret
  expected_pn = 0
  crypto_chunks = {}
  pushed = 0
  sni = nil

  for_each_epb capture_path, (payload, packet_start, packet_end, epb_idx) ->
    e, l3_off = eth_mod.parse payload, packet_start
    return false unless e

    ip_pkt, l4_off = ip_mod.parse payload, l3_off
    return false unless ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP

    udp_dgram, l7_off = udp_mod.parse payload, l4_off
    return false unless udp_dgram

    q, _ = quic_mod.parse payload, l7_off
    return false unless q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0
    return false unless q.dst_connection_id == initial_dcid

    quic_packet = payload\sub l7_off, packet_end
    print "INFO\tlunatik: extract_sni stage=decrypt epb=#{epb_idx}"
    q_pkt, _ = quic_mod.parse quic_packet, 1
    assert q_pkt and q_pkt.pn_off, "invalid QUIC packet for decryption"
    print "INFO\tlunatik: extract_sni parsed_quic packet_len=#{#quic_packet} pn_off=#{q_pkt.pn_off} pkt_length=#{tostring q_pkt.pkt_length} expected_pn=#{expected_pn}"
    if q_pkt.pkt_length and q_pkt.pn_off
      logical_end = (q_pkt.pn_off - 1) + q_pkt.pkt_length
      if logical_end > 0 and logical_end < #quic_packet
        quic_packet = quic_packet\sub 1, logical_end
        print "INFO\tlunatik: extract_sni trimmed_quic packet_len=#{#quic_packet}"

    dec = bruteforce_decrypt_initial quic_packet, q_pkt, key, iv, expected_pn
    return false unless dec
    plaintext = dec.plaintext
    expected_pn = dec.pn + 1 if dec.pn >= expected_pn
    pushed += 1

    print "INFO\tlunatik: extract_sni stage=sni_from_plaintext plaintext_len=#{#plaintext}"
    append_crypto_chunks crypto_chunks, plaintext
    tls_stream = crypto_stream_from_chunks crypto_chunks
    sni = sni_from_tls tls_stream
    return sni ~= nil

  assert pushed > 0, "no client Initial datagrams pushed for selected DCID"
  {
    :pushed
    :sni
  }

capture_path = resolve_capture_path!
flow = scan_first_initial capture_path
print "INFO\tlunatik: backend=lunatik capture=#{capture_path}"
print "INFO\tlunatik: epb_blocks_seen=#{flow.epb_count} first_initial_epb=#{flow.first.epb_idx}"

assert_test "Kernel QUIC Google capture parses expected L2/L3/L4 metadata", ->
  f = flow.first
  assert bin2hex(f.e.dst) == EXPECTED.dst_mac, "dst mac mismatch: #{bin2hex f.e.dst}"
  assert bin2hex(f.e.src) == EXPECTED.src_mac, "src mac mismatch: #{bin2hex f.e.src}"
  assert ip_mod.ip2s(f.ip_pkt.src) == EXPECTED.src_ip, "src ip mismatch: #{ip_mod.ip2s f.ip_pkt.src}"
  assert ip_mod.ip2s(f.ip_pkt.dst) == EXPECTED.dst_ip, "dst ip mismatch: #{ip_mod.ip2s f.ip_pkt.dst}"
  assert f.udp_dgram.spt == EXPECTED.udp_spt, "udp source port mismatch: #{f.udp_dgram.spt}"
  assert f.udp_dgram.dpt == EXPECTED.udp_dpt, "udp destination port mismatch: #{f.udp_dgram.dpt}"
  assert f.q.long_header == true, "expected QUIC long header"
  assert f.q.pkt_type == 0x00, "expected QUIC Initial packet"
  print "INFO\tlunatik: L2 src_mac=#{bin2hex f.e.src} dst_mac=#{bin2hex f.e.dst}"
  print "INFO\tlunatik: L3 src_ip=#{ip_mod.ip2s f.ip_pkt.src} dst_ip=#{ip_mod.ip2s f.ip_pkt.dst}"
  print "INFO\tlunatik: L4 udp_src=#{f.udp_dgram.spt} udp_dst=#{f.udp_dgram.dpt}"
  print "INFO\tlunatik: QUIC dcid=#{bin2hex f.q.dst_connection_id} version=#{f.q.version}"

assert_test "Kernel QUIC Google capture extracts SNI using lunatik backend", ->
  sni_flow = extract_sni capture_path, flow.initial_dcid
  extracted_sni = sni_flow.sni
  assert extracted_sni == EXPECTED.sni, "expected SNI #{EXPECTED.sni}, got #{tostring extracted_sni}"
  print "INFO\tlunatik: pushed_initial_packets=#{sni_flow.pushed} expected_sni=#{EXPECTED.sni} extracted_sni=#{extracted_sni}"

print "  --> lib.crypto.lunatik.kernel.quic_google_capture: #{tests_passed}/#{tests_passed + tests_failed}"
