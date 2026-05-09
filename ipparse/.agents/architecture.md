# Architecture — module conventions

## parse / pack / new contract

Every protocol module (Ethernet, IPv4, TCP, QUIC, …) follows the same
three-function contract:

| Function | Signature | Purpose |
|----------|-----------|---------|
| `parse`  | `(self=data, off=1, ...) =>` | Binary string → structured table + next offset |
| `pack`   | `(self=table) =>`            | Structured table → binary string (also `__tostring`) |
| `new`    | `(self=table) =>`            | Construct + validate a table, set its metatable |

`parse` always returns `(result_table, next_offset)`.  
`pack` is set as `__tostring` on the module's metatable so `"#{obj}"` works.

## Metatable-based OOP (no `class`)

```moonscript
pack = => ...  -- serialiser, set as __tostring

_mt =
  __tostring: pack
  __index: (k) => ...   -- optional: flag access, etc.
  __newindex: (k, v) => ...

parse = (off=1) =>
  ..., data_off = su ">...", @, off
  setmetatable { :field1, :field2, :off, :data_off }, _mt
  -- returns (table, data_off)

new = =>
  @field or= default
  setmetatable @, _mt
```

All objects carry `:off` (start of their header in the original data) and
`:data_off` (start of the payload / next layer).

## Layered parsing

Typically driven by a pcap loop:

```
pcap.parse(data)                 -- lib/pcap.moon  → raw packets
  → ethernet.parse(pkt)          -- l2/
    → ip.parse(pkt, eth.data_off) -- l3/ (dispatches ip4/ip6)
      → quic.parse(pkt, ip.data_off) -- l4/
        → quic.v1 decrypt/frames    -- l4/quic/
          → tls.client_hello        -- l7/tls/
```

## fun.moon primitives

| Function | Use |
|----------|-----|
| `bidirectional(t)` | Add `value→key` reverse lookup via `__index` |
| `memo(fn)` / `memoN(fn)` | Memoize single- / multi-arg functions |
| `iter(t)` | Chainable iterator: `.map`, `.filter`, `.reduce`, `.each`, … |
| `opairs(t)` | Sorted `pairs` (stable output) |
| `protected(fn)` | `xpcall` wrapper with traceback |

## QUIC specifics

- `l4/quic/init.moon` — long/short header dispatch, loads version modules.
- `l4/quic/v1.moon` — QUIC v1 long-header parsing.
- `l4/quic/crypto.moon` — header-protection removal, key derivation (RFC 9001).
- `l4/quic/frames.moon` — CRYPTO/STREAM/ACK/… frame parsing.
- `l7/quic/init.moon` — SNI extraction from Initial packets.
- `lib/crypto/` — AEAD (AES-GCM), HKDF, OpenSSL FFI wrappers.

## lib/ support modules

| Module | Role |
|--------|------|
| `lib/pcap.moon` | PCAP/PCAPNG reader |
| `lib/bit_compat.moon` | `bit` ops for Lua 5.1 / LuaJIT / 5.3+ |
| `lib/pack_compat.moon` | `string.pack/unpack` shim |
| `lib/hkdf.moon` | HKDF (HMAC-based key derivation) |
| `lib/crypto/aead.moon` | AEAD interface |
| `lib/crypto/openssl_aead.moon` | OpenSSL FFI AEAD backend |
