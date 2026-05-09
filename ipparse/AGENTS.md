# ipparse — AGENTS.md

MoonScript/Lua library for parsing and spoofing network packets.
Designed for [Lunatik](https://github.com/luainkernel/lunatik) (kernel Lua),
but usable in plain LuaJIT/Lua 5.1+.

## Project structure

```
ipparse/
├── init.moon          # Shared helpers: bin2hex, hexdump, hex2bin, dump, …
├── fun.moon           # Functional primitives: iter, memo, bidirectional, …
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

lua tests/crypto/aead.lua   # Run a test (no unified runner yet)

ldoc .              # Generate HTML docs in doc/  (uses config.ld)
```

## Code conventions

- **No `class`** — use factory functions + `setmetatable`.
- Every protocol module exports `parse`, `pack`, and/or `new`.
- LDoc on every public function; see `.agents/moonscript.md`.
- Functional style: `fun.moon` primitives (`iter`, `memo`, `bidirectional`, …).
- `bidirectional` tables map both `name→value` and `value→name`.

See `.agents/moonscript.md` for MoonScript syntax, fat-arrow, scoping pitfalls.  
See `.agents/architecture.md` for the parse/pack/new contract and OOP pattern.

## License

MIT OR GPL-2.0-only
