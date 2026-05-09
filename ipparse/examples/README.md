# ipparse Examples

## parse_real_quic.moon

Demonstrates complete L2-L7 packet parsing from a real QUIC packet captured in a `.pcap` or `.pcapng` file.

### Running the Example

**Direct (from anywhere):**
```bash
/PATH/TO/ipparse/examples/parse_real_quic.moon /path/to/capture.pcap
```

**Via Make (default: `quic.pcapng` at project root):**
```bash
make example
```

**Via Shell Script:**
```bash
./examples/parse_real_quic.sh /path/to/capture.pcapng
```

### What It Does

Parses a real CloudFlare QUIC packet and displays:

- **Layer 2 (Ethernet):** Source and destination MAC addresses, protocol type
- **Layer 3 (IPv6):** Source and destination IPv6 addresses, next header type
- **Layer 4 (UDP):** Source and destination ports, packet length
- **Layer 7 (QUIC):** Long header flag, version, DCID, encrypted packet length

### Sample Output

```
================================================================================
QUIC Packet Parser - Real Packet from quic.pcapng
================================================================================

Layer 2 (Ethernet):
  src MAC: e08f4cc891fa
  dst MAC: a42bb0f2c1fc
  protocol: 0x86dd

Layer 3 (IPv6):
  src: 2001:0867:000f:a009:0000:0000:0000:0f13
  dst: 2606:4700:4400:0000:0000:0000:ac40:996e
  next header: 17

Layer 4 (UDP):
  src port: 44339
  dst port: 443

Layer 7 (QUIC):
  long header: true
  version: 0x00000001
  DCID: 133a971cdef32a97
  packet length: 949

Layer 7 (SNI Extraction - RFC 9001):
  ✓ Initial secret derived from DCID
  ✓ Decryption keys derived (3x)
    - Key: 98d052be30563aff8180f7cbbaf04a8d
    - IV: 9a872f755c9c173df6d21846
    - HP Key: b7ee662400b75622ffa4835cf37930cd

  ℹ SNI extraction requires header protection removal
    and packet number recovery (see RFC 9001 §5.4)

================================================================================
✓ Successfully parsed QUIC packet from L2 to L7
================================================================================
```

### Technical Details

- **Source:** Real packet from [QaCafe CloudFlare QUIC samples](https://www.qacafe.com/resources/sample-captures-for-quic-doh-communityid-wpa3-cloudshark-3-10/)
- **Format:** Hex string embedded in code (avoids binary I/O dependencies)
- **Language:** MoonScript (compiles to Lua)
- **Requires:** luajit (for FFI-based binary operations)

## dns_parse.moon

Tutorial demonstrating how to parse DNS queries and answers from raw network packets.

### What It Does

Parses two sample packets:
- **DNS Query:** A DNS A record query for "example.com"
- **DNS Answer:** The corresponding DNS response with the A record answer (93.184.216.34)

Demonstrates parsing through:
- Layer 2 (Ethernet): MAC addresses and EtherType
- Layer 3 (IPv4): Source/destination IP addresses and protocol
- Layer 4 (UDP): Source/destination ports and length
- Layer 7 (DNS): Transaction ID, flags, questions, and resource records

### Running the Example

```bash
moon examples/dns_parse.moon
```

### Sample Output

```
-- Layer 2: Ethernet --
Destination MAC: 00:01:02:03:04:05
Source MAC: 06:07:08:09:0a:0b
EtherType: 0x0800 (IP4)

-- Layer 3: IP --
Version: 4
Source IP: 192.168.0.2
Destination IP: 192.168.0.1
Protocol: 0x11 (UDP)

-- Layer 4: UDP --
Source Port: 49155
Destination Port: 53
Length: 37

-- Layer 7: DNS --
DNS Transaction ID: 0x1234
DNS Flags: 0x0100
  Query/Response: Query
  Recursion Desired: Yes
Number of Questions: 1
Number of Answers: 0
  Question 1:
    Name: example.com
    Type: A (0x0001)
    Class: IN (0x0001)
```

### Technical Details

- **Language:** MoonScript (compiles to Lua)
- **Format:** Hex strings embedded in code (simulated packets)
- **Includes:** DNS label compression pointer handling in the answer

## tls_parse.moon

Tutorial demonstrating how to extract Server Name Indication (SNI) from TLS ClientHello messages.

### What It Does

Parses a TLS handshake packet to extract:
- Layer 2 (Ethernet): MAC addresses and EtherType
- Layer 3 (IPv4): Source/destination IP addresses
- Layer 4 (TCP): Ports, flags, sequence numbers
- Layer 7 (TLS): Record layer, handshake messages, ClientHello structure
- **SNI:** Server Name Indication extension (extracts "example.com")

### Running the Example

```bash
# With embedded sample data
moon examples/tls_parse.moon

# With hex file input
moon examples/tls_parse.moon /path/to/packet.hex
```

### Sample Output

```
-- Layer 2: Ethernet --
Destination MAC: 00:01:02:03:04:05
Source MAC: 06:07:08:09:0a:0b
EtherType: 0x0800 (IP4)

-- Layer 3: IP --
Version: 4
Source IP: 192.168.0.2
Destination IP: 192.168.0.1
Protocol: 0x06 (TCP)

-- Layer 4: TCP --
Source Port: 49153
Destination Port: 443
Flags: ACK PSH (0x18)

-- Layer 7: TLS --
TLS Record Type: 0x16 (handshake)
TLS Version in Record: 0x0303
TLS Record Payload Length: 66

Handshake Message Type: 0x01 (client_hello)
Handshake Message Length: 62

ClientHello Protocol Version: 0x0303
ClientHello Extensions Block Length (raw): 20
  Found Extension: Type 0x0000 (server_name), Data Length 16
  > Found Server Name Indication (SNI) Extension
    SNI Host Name: example.com
```

### Technical Details

- **Language:** MoonScript (compiles to Lua)
- **Format:** Hex string embedded in code (simulated packet)
- **TLS Version:** 1.2 (0x0303)
- **Cipher Suite:** TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)

## quic_parse.moon

Tutorial demonstrating how to extract SNI from QUIC Initial packets (simulated).

### What It Does

Parses a QUIC packet with simulated header/payload protection to extract:
- Layer 2-4: Ethernet, IPv4, UDP
- Layer 7 (QUIC): Long header, version, DCID, SCID
- **SNI:** Extracted from TLS ClientHello within QUIC CRYPTO frame

**Note:** This example uses simulated protection for educational purposes. Real QUIC requires cryptographic key derivation (HKDF) and AEAD decryption.

### Running the Example

```bash
moon examples/quic_parse.moon
```

### Sample Output

```
-- Layer 2: Ethernet --
Destination MAC: 00:01:02:03:04:05
Source MAC: 06:07:08:09:0a:0b
EtherType: 0x0800 (IP4)

-- Layer 3: IP --
Version: 4
Source IP: 192.168.0.2
Destination IP: 192.168.0.1
Protocol: 0x11 (UDP)

-- Layer 4: UDP --
Source Port: 49154
Destination Port: 443

-- Layer 7: QUIC --
QUIC Header Form: LONG
QUIC Long Packet Type: INITIAL (0x00)
QUIC Version: 0x00000001
QUIC DCID: aaaaaaaaaaaaaaaa
QUIC SCID: bbbbbbbbbbbbbbbb
  Found QUIC CRYPTO Frame, Offset: 0, Length: 66
    TLS Handshake Message Type: client_hello
    TLS Handshake Message Length: 62
    ClientHello Protocol Version: 0x0303
    ClientHello Extensions Block Length (raw): 20
      > Found Server Name Indication (SNI) Extension
        SNI Host Name: example.com
```

### Technical Details

- **Language:** MoonScript (compiles to Lua)
- **Format:** Hex string with simulated XOR protection
- **QUIC Version:** 1 (draft-32 or RFC 9000)
- **Protection:** Simulated (real QUIC uses AEAD with HKDF-derived keys)
- **Reference:** RFC 9001 (QUIC TLS Integration)

## quic_sni_extraction_demo.moon

Demonstrates QUIC SNI extraction with actual cryptographic operations.

### What It Does

Uses the full QUIC parsing stack with real crypto backend to:
- Parse PCAP/PCAPNG files
- Extract QUIC packets
- Derive initial secrets using HKDF
- Remove header protection
- Decrypt payload
- Extract SNI from ClientHello

### Running the Example

```bash
moon examples/quic_sni_extraction_demo.moon /path/to/capture.pcapng
```

### Requirements

- LuaJIT with FFI
- Crypto backend (OpenSSL, mbedTLS, or WolfSSL)
- PCAP/PCAPNG file with QUIC Initial packets

## sni_success_demo.moon

Simple demonstration of successful SNI extraction from TLS.

### What It Does

Minimal example showing the SNI extraction workflow without full packet parsing.

### Running the Example

```bash
moon examples/sni_success_demo.moon
```

### Technical Details

- Focuses on the TLS SNI extension parsing only
- Useful for understanding the SNI data structure in isolation

