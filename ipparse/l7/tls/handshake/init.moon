--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- TLS Handshake Parsing and Packing Module
-- This module provides utilities for parsing and packing TLS handshake messages.
-- It supports handling various handshake message types, ciphers, compressions, and extensions.
--
-- ### Features
-- - Parse and pack TLS handshake messages.
-- - Support for various handshake message types, ciphers, and extensions.
--
-- ### TLS Handshake Structure
-- ```
-- Handshake {
--   type (8): Handshake message type.
--   len (24): Length of the handshake message.
--   payload (variable): Handshake message payload.
-- }
-- ```
--
-- References:
-- - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
-- - RFC 6066: TLS Extensions
--
-- @module tls.handshake

pack: sp, unpack: su = string
:bidirectional = require"ipparse.fun"
parse: parse_extension = require"ipparse.l7.tls.handshake.extension"

--- Packs a TLS handshake message into a binary string.
-- Constructs the binary representation of the handshake message.
-- @tparam table self The handshake message object.
-- @treturn string Binary string representing the packed handshake message.
pack = =>
  sp ">B BH", @type, (@len >> 16), (@len & 0xffff)

_mt =
  --- Converts the handshake message object to a binary string.
  -- @treturn string Binary string representing the handshake message.
  __tostring: pack

--- Parses a binary string into a TLS handshake message structure.
-- Extracts the handshake type, length, and payload from the binary string.
-- @tparam string self The binary string containing the handshake message.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @treturn table Parsed handshake message as a table.
-- @treturn number The next offset after parsing.
parse = (off=1) =>
  _type, _len, len, _off = su ">B BH", @, off
  len += (_len << 16)
  setmetatable({type: _type, :len}, _mt), _off

--- Parses a list of cipher suites from a binary string.
-- Extracts cipher suite codes from the binary string.
-- @tparam string self The binary string containing the cipher suites.
-- @treturn {number} Array of cipher suite codes.
parse_ciphers = => [su ">H", @, i for i = 1, #@, 2]

--- Parses a list of compression methods from a binary string.
-- Extracts compression method codes from the binary string.
-- @tparam string self The binary string containing the compression methods.
-- @treturn {number} Array of compression method codes.
parse_compressions = => [su "B", @, i for i = 1, #@]

--- Iterates over TLS extensions in a binary string.
-- Extracts extensions one by one from the binary string.
-- @tparam string self The binary string containing the extensions.
-- @tparam[opt=1] number off Offset to start parsing from. Defaults to 1.
-- @tparam[opt=#self] number len Length of the extensions data. Defaults to the full string length.
-- @treturn function Iterator function returning each parsed extension.
iter_extensions = (off=1, len=#@) =>
  _max = off+len
  ->
    if off < _max
      extension, off = parse_extension @, off
      extension

--- TLS Handshake Message Types
-- Provides a mapping of handshake message type codes to their names.
-- @field[type=table] message_types Bidirectional mapping of handshake message type codes and names.
message_types = bidirectional {
  [0x00]: "hello_request"
  [0x01]: "client_hello"
  [0x02]: "server_hello"
  [0x04]: "new_session_ticket"
  [0x0b]: "certificate"
  [0x0c]: "server_key_exchange"
  [0x0d]: "certificate_request"
  [0x0e]: "server_hello_done"
  [0x0f]: "certificate_verify"
  [0x10]: "client_key_exchange"
  [0x11]: "finished"
  [0x12]: "certificate_url"
  [0x13]: "certificate_status"
  [0x14]: "supplemental_data"
  [0x15]: "key_update"
}

--- TLS Cipher Suites
-- Provides a mapping of cipher suite codes to their names.
-- @field[type=table] ciphers Bidirectional mapping of cipher suite codes and names.
ciphers = bidirectional {
  [0x0005]: "TLS_RSA_WITH_RC4_128_SHA"
  [0x000a]: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
  [0x003c]: "TLS_RSA_WITH_AES_128_CBC_SHA256"
  [0x003d]: "TLS_RSA_WITH_AES_256_CBC_SHA256"
  [0x009c]: "TLS_RSA_WITH_AES_128_GCM_SHA256"
  [0x009d]: "TLS_RSA_WITH_AES_256_GCM_SHA384"
  [0x009e]: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
  [0x009f]: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
  [0xc008]: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
  [0xc012]: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
  [0xc023]: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
  [0xc024]: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
  [0xc027]: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
  [0xc028]: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
  [0xc02b]: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
  [0xc02c]: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  [0xc02f]: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  [0xc030]: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  [0x1301]: "TLS_AES_128_GCM_SHA256"
  [0x1302]: "TLS_AES_256_GCM_SHA384"
  [0x1303]: "TLS_CHACHA20_POLY1305_SHA256"
  [0xcca8]: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
  [0xcca9]: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
}

--- TLS Compression Methods
-- Provides a mapping of compression method codes to their names.
-- @field[type=table] compressions Bidirectional mapping of compression method codes and names.
compressions = bidirectional {
  [0x00]: "NULL"
  [0x01]: "DEFLATE"
  [0x02]: "LZS"
  [0x03]: "SNAPPY"
  [0xff]: "unknown"
}

--- TLS Extensions
-- Provides a mapping of extension codes to their names.
-- @field[type=table] extensions Bidirectional mapping of extension codes and names.
extensions = bidirectional {
  [0x00]: "server_name"
  [0x01]: "max_fragment_length"
  [0x02]: "client_certificate_url"
  [0x03]: "trusted_ca_keys"
  [0x04]: "truncated_hmac"
  [0x05]: "status_request"
  [0x06]: "user_mapping"
  [0x07]: "client_authz"
  [0x08]: "server_authz"
  [0x09]: "cert_type"
  [0x0a]: "supported_groups"
  [0x0b]: "ec_point_formats"
  [0x0c]: "srp"
  [0x0d]: "signature_algorithms"
  [0x0e]: "use_srtp"
  [0x0f]: "heartbeat"
  [0x10]: "application_layer_protocol_negotiation"
  [0x11]: "status_request_v2"
  [0x12]: "signed_certificate_timestamp"
  [0x13]: "client_certificate_type"
  [0x14]: "server_certificate_type"
  [0x15]: "padding"
  [0x16]: "encrypt_then_mac"
  [0x17]: "extended_master_secret"
  [0x18]: "token_binding"
  [0x19]: "cached_info"
  [0x1a]: "tls_ticket_early_data_info"
  [0x1b]: "pre_shared_key"
  [0x1c]: "early_data"
  [0x1d]: "supported_versions"
  [0x1e]: "cookie"
  [0x1f]: "psk_key_exchange_modes"
  [0x20]: "ticket_early_data_info"
  [0x21]: "test"
  [0x22]: "compress_certificate"
  [0x23]: "record_size_limit"
  [0xff]: "unknown"
}

:parse, :pack, :ciphers, :compressions, :extensions, :message_types, :parse_ciphers, :parse_compressions, :iter_extensions
