# ipparse Test Suite

This directory contains tests for the ipparse library. Tests are organized by protocol layer and functionality.

## Test Organization

### Crypto Tests (`tests/crypto/`)

Tests for cryptographic operations used by QUIC and TLS.

- **aead.lua** - Authenticated Encryption with Associated Data (AES-128-GCM)
- **comp.lua** - Compression/decompression operations
- **hkdf.lua** - HMAC-based Extract-and-Expand Key Derivation Function
- **rng.lua** - Random number generation
- **shash.lua** - Secure hash operations
- **skcipher.lua** - Symmetric key cipher operations

### Layer 2 Tests (`tests/l2/`)

Tests for data link layer protocols.

- **test_ethereum.lua/moon** - Ethernet frame parsing and packing

### Layer 3 Tests (`tests/l3/`)

Tests for network layer protocols.

- **test_checksum.lua/moon** - IP/UDP/TCP checksum validation
- **test_ip.lua/moon** - Generic IP parsing (IPv4/IPv6)
- **test_ip4.lua/moon** - IPv4-specific parsing and packing
- **test_ip6.lua/moon** - IPv6-specific parsing and packing

### Layer 4 Tests (`tests/l4/`)

Tests for transport layer protocols.

- **test_tcp.lua/moon** - TCP segment parsing and packing
- **test_udp.lua/moon** - UDP datagram parsing and packing

### QUIC Tests (`tests/l4/quic/`)

Comprehensive tests for QUIC protocol implementation.

- **test_frames.lua/moon** - QUIC frame parsing (STREAM, ACK, CRYPTO, etc.)
- **test_header.lua/moon** - QUIC header parsing (long and short headers)
- **test_integration.lua/moon** - End-to-end QUIC packet parsing
- **test_keys.lua/moon** - QUIC key derivation (HKDF-based)
- **test_protection.lua/moon** - QUIC header protection and payload encryption
- **test_varint.lua/moon** - QUIC variable-length integer encoding

### Layer 7 QUIC Tests (`tests/l7/quic/`)

Tests for QUIC session management and SNI extraction.

- **test_google_capture_backends.lua/moon** - Test with real Google QUIC captures
- **test_session.lua/moon** - QUIC session state management
- **test_sni.lua/moon** - Server Name Indication extraction from QUIC

### Layer 7 Tests (`tests/l7/`)

Tests for application layer protocols.

- **test_dns.lua/moon** - DNS message parsing (queries, responses, EDNS)

### Crypto Backend Tests (`tests/lib/crypto/`)

Tests for different cryptographic backend implementations.

- **test_ffi_mbedtls.lua/moon** - mbedTLS FFI backend
- **test_ffi_wolfssl.lua/moon** - WolfSSL FFI backend
- **test_lunatik.lua/moon** - Lunatik kernel crypto backend
- **test_lunatik_kernel.lua** - Lunatik kernel-specific tests

## Running Tests

### Individual Tests

Run a specific test file with LuaJIT:

```bash
luajit tests/l2/test_ethernet.lua
luajit tests/l4/test_udp.lua
```

Or with MoonScript (requires compilation):

```bash
moon tests/l2/test_ethernet.moon
```

### All Tests

The project uses a Makefile for building and testing:

```bash
make                # Compile all .moon → .lua
make test           # Run all tests (if test runner is configured)
```

Note: As of this writing, there is no unified test runner. Tests are run individually.

## Test Format

Tests are provided in both Lua (`.lua`) and MoonScript (`.moon`) formats. The Lua files are the compiled output of the MoonScript files.

- **MoonScript (`.moon`)**: Source code, human-readable, easier to modify
- **Lua (`.lua`)**: Compiled output, directly executable with LuaJIT

When adding new tests, write them in MoonScript and compile with `moonc`.

## Test Coverage

The test suite covers:

- Protocol parsing (Ethernet, IPv4, IPv6, TCP, UDP, DNS, QUIC, TLS)
- Protocol packing (reconstructing packets from parsed objects)
- Cryptographic operations (AEAD, HKDF, key derivation)
- Edge cases (malformed packets, boundary conditions)
- Interoperability (different crypto backends)

## Adding New Tests

1. Create a new `.moon` file in the appropriate subdirectory
2. Write tests using `assert` for validation
3. Compile with `moonc your_test.moon`
4. Run with `luajit your_test.lua`
5. Update this README if adding a new test category

## Test Data

Some tests use embedded hex strings for reproducibility. Others may require external PCAP files (e.g., QUIC tests with real captures). Ensure any external test data is documented in the test file comments.
