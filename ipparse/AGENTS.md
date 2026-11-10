# ipparse — AGENTS.md

MoonScript/Lua library for parsing and spoofing network packets.
Designed for [Lunatik](https://github.com/luainkernel/lunatik) (kernel Lua),
but usable in plain LuaJIT/Lua 5.1+.

## Project structure

```
ipparse/
├── init.moon          # Shared helpers: bin2hex, hexdump, hex2bin, dump, …
├── fun.moon           # Facade re-exporting fun/ primitives: iter, memo, bidirectional, …
├── fun/               # Functional primitives, loadable separately
│   ├── tables.moon    #   bidirectional, zero_indexed, opairs (used by protocols)
│   ├── memo.moon      #   memo, memoN
│   ├── iter.moon      #   iter, wrap, range, generate
│   └── protected.moon #   protected, leak_debug
├── l2/                # Layer 2 — Ethernet
├── l3/                # Layer 3 — IPv4, IPv6, fragmented IP
├── l4/                # Layer 4 — TCP, UDP, QUIC (with crypto/frames)
├── l7/                # Layer 7 — DNS, TLS, QUIC SNI
├── lib/               # Support libs: pcap, crypto (AEAD/HKDF), bit compat, …
├── tests/             # Test scripts (Lua)
├── examples/          # Usage examples (MoonScript)
├── .agents/           # Agent guidance
│   ├── moonscript.md  # MoonScript syntax, LDoc, pitfalls  ← read first
│   └── architecture.md # Module conventions (parse/pack/new pattern, OOP)
├── config.ld          # LDoc configuration
└── Makefile
```

## Build, install, test, docs

```bash
make                # Compile all .moon → .lua  (moonc .)
sudo make install   # Copy .lua to /lib/modules/lua/ipparse/
make clean          # Delete generated .lua files

make test           # Run the full test suite (tests/run_all via LuaJIT)
sudo make test-lunatik  # Run kernel (Lunatik) crypto tests on the host
make -C .. vm-test  # Full suite (userspace + kernel) in a virtme-ng VM
                    # on the pinned LTS kernel — see ../tools/vmtest/

ldoc .              # Generate HTML docs in doc/  (uses config.ld)
```

## Code conventions

- **No `class`** — use factory functions + `setmetatable`.
- Every protocol module exports `parse`, `pack`, and/or `new`.
- LDoc on every public function; see `.agents/moonscript.md`.
- Functional style: `fun.moon` primitives (`iter`, `memo`, `bidirectional`, …).
- `bidirectional` tables map both `name→value` and `value→name`.

## Kernel stack budget

Under Lunatik a kernel thread has a 16 KiB stack, and `lunatik_maxccalls`
lets Lua consume 5/8 of it before raising "C stack overflow". Loading a
module costs C stack: every nested `require` pushes frames, and the Lua
parser itself is recursive, so `ipparse.fun` first parsed at the bottom of a
require chain has already overflowed twice in practice.

Rules for entry modules (any module a user may `require` directly):

- Make `require "ipparse"` the **first** `require`, so the shared base is
  parsed at the shallowest possible depth.
- Internal modules must never load the `ipparse.fun` facade; they take the
  small `ipparse.fun.tables` subset instead.
- Do not add deeply nested function expressions to modules loaded
  everywhere: each nesting level counts against the loader's stack.

Measured by the stack canary (maximum number of nested requires an entry
module can be first loaded from):

| Module | Source | Bytecode |
|---|---|---|
| `ipparse` (shared base) | 8 | ≥ 12 |
| `l2.ethernet`, `l4.tcp`, `l7.dns`, `l4.quic.frames`, `l7.tls.handshake` | 6 | ≥ 9 |
| `l3.ip`, `l3.ip4`, `l3.ip6`, `l4.udp` | 5 | ≥ 11 |
| `l4.quic` | 4 | 11 |
| `l7.quic.session` | 3 | 9 |
| `l7.quic` | 2 | 8 |
| `ipparse.fun` facade, `ipparse.fun.protected` | 0–1 | ≥ 12 |

Before the `ipparse.fun` split, every protocol module was at 0. Bytecode is
recommended in production, and required to load the `ipparse.fun` facade or
`ipparse.fun.protected` anywhere below the shallowest level.

`make install BYTECODE=1` installs the modules precompiled instead of as
source, which skips the recursive Lua parser at load time. The compiler must
be Lunatik's `lunatic` (from a Lunatik build; pass it with
`LUNATIC=/path/to/bin/lunatic`), never the system `luac`, whose chunks the
kernel rejects. `BYTECODE=1` keeps debug information, so kernel error messages
remain readable; `BYTECODE=strip` strips it for smaller files, at the cost of
`?:?:` locations in errors. The test VM plays the kernel suite twice: once
from source, then again after reinstalling ipparse as bytecode.

The mechanical guard is `tests/test_lunatik_kernel_stack_canary.moon` and its
`REQUIRED_DEPTH` constant: it also checks that each entry module loaded the
base first and did not drag in the heavy `fun` facade. Never lower
`REQUIRED_DEPTH` to make the test pass.

## Test coverage

`make coverage` runs the suite under LuaJIT and Lua 5.4 with luacov and prints
a cumulative report. `tests/coverage_baseline` holds the reference total; the
non-blocking CI `coverage` job warns (without failing) when it drops below it.
OpenSSL and mbedTLS are optional: when they are loadable (e.g. add openssl
mbedtls to the nix-shell, as `tests/ffi_libs.sh` expects) the FFI crypto
backends run, otherwise their tests skip themselves.

See `.agents/moonscript.md` for MoonScript syntax, fat-arrow, scoping pitfalls.  
See `.agents/architecture.md` for the parse/pack/new contract and OOP pattern.

## License

MIT OR GPL-2.0-only
