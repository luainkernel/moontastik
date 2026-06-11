-- ipparse/lib/sha.lua
-- Pure Lua SHA256 and HMAC implementation for Lua 5.3/5.4+
-- Focuses on binary input/output and native bitwise operations.

-- SPDX-FileCopyrightText: (c) 2024-2025 Gemini Code Assist
-- SPDX-License-Identifier: MIT

local unpack, table_concat, byte, char, string_rep, sub, gsub, gmatch, string_format, math_min, math_max, tonumber, type, math_huge =
   table.unpack or unpack, table.concat, string.byte, string.char, string.rep, string.sub, string.gsub, string.gmatch, string.format, math.min, math.max, tonumber, type, math_huge

local string_pack, string_unpack
if string.pack and string.unpack then
  string_pack = string.pack -- Lua 5.3+
  string_unpack = string.unpack -- Lua 5.3+
else
  local pack_compat = require "ipparse.lib.pack_compat"
  string_pack = pack_compat.pack
  string_unpack = pack_compat.unpack
end

-- Check for native 32-bit or 64-bit integers and bitwise operators (Lua 5.3+)
local Lua_has_native_bitwise = type(1 & 1) == 'number'

if not Lua_has_native_bitwise then
    error("This sha.lua requires Lua 5.3+ with native bitwise operators.")
end

-- Basic 32-bit Bitwise Functions (using native operators)
local bit = bit or {}
local AND, OR, XOR, SHL, SHR, ROL, ROR, NOT

AND = bit.band or function(x, y) return x & y end
OR  = bit.bor  or function(x, y) return x | y end
XOR = bit.bxor or function(x, y) return x ~ y end
NOT = bit.bnot or function(x) return ~x end

-- Lua 5.3+ shifts handle negative numbers correctly for signed int32,
-- but we work with unsigned 32-bit concepts.
-- For unsigned 32-bit, >> is logical right shift, << is left shift.
-- ROL/ROR need careful implementation for 32-bit unsigned.

-- Assuming standard Lua 5.3+ behavior where bitwise ops treat numbers as signed 32-bit,
-- but results are within number range. We need to ensure unsigned 32-bit behavior.
-- A common way is to mask with 0xFFFFFFFF.
local MASK32 = 0xFFFFFFFF

SHL = function(x, n) return (x << n) & MASK32 end
SHR = function(x, n) return (x >> n) & MASK32 end -- Logical right shift

ROL = function(x, n)
    n = n % 32
    return ((x << n) & MASK32) | ((x >> (32 - n)) & MASK32)
end

ROR = function(x, n)
    n = n % 32
    return ((x >> n) & MASK32) | ((x << (32 - n)) & MASK32)
end

-- Binary Packing Utilities
local function BIN32_BE(val) -- Big Endian 32-bit
   return string_pack(">I4", val)
end

local function BIN64_BE(val) -- Big Endian 64-bit (assumes native 64-bit integers or LuaJIT FFI i64)
   -- This might need adjustment based on the exact Lua 5.4 build's integer type.
   -- If Lua 5.4 is built with LUA_INT_TYPE=LUA_INT_INT (32-bit), this needs to pack hi/lo parts.
   -- For simplicity, assuming standard 64-bit integer build.
   return string_pack(">I8", val)
end

-- SHA256 Constants (Initial Hash Values H[0..7] and Round Constants K[0..63])
-- These are hardcoded from the SHA-2 spec.
local sha256_H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
}

local sha256_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xef983bda, 0xfc930062, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9ca4f7, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

-- SHA256 Compression Function (adapted from sha2.lua INT64 branch logic)
-- Processes a single 64-byte block. H is modified in place.
local function sha256_feed_64(H, block)
    local W = {} -- Message schedule

    -- Prepare message schedule W
    for j = 0, 15 do
        -- Unpack 4 bytes (big-endian) into a 32-bit number
        W[j] = string_unpack(">I4", block, j * 4 + 1)
    end

    for j = 16, 63 do
        -- Sigma0(x) = ROR(x, 7) XOR ROR(x, 18) XOR SHR(x, 3)
        local s0 = XOR(XOR(ROR(W[j-15], 7), ROR(W[j-15], 18)), SHR(W[j-15], 3))
        -- Sigma1(x) = ROR(x, 17) XOR ROR(x, 19) XOR SHR(x, 10)
        local s1 = XOR(XOR(ROR(W[j-2], 17), ROR(W[j-2], 19)), SHR(W[j-2], 10))
        W[j] = (s0 + s1 + W[j-7] + W[j-16]) & MASK32 -- Addition modulo 2^32
    end

    -- Initialize working variables
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

    -- Compression loop
    for j = 0, 63 do
        -- Sum1(x) = ROR(x, 6) XOR ROR(x, 11) XOR ROR(x, 25)
        local sum1 = XOR(ROR(e, 6), ROR(e, 11), ROR(e, 25))
        -- Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
        local ch = XOR(AND(e, f), AND(NOT(e), g))
        local temp1 = (h + sum1 + ch + sha256_K[j+1] + W[j]) & MASK32

        -- Sum0(x) = ROR(x, 2) XOR ROR(x, 13) XOR ROR(x, 22)
        local sum0 = XOR(ROR(a, 2), ROR(a, 13), ROR(a, 22))
        -- Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
        local maj = XOR(AND(a, b), AND(a, c), AND(b, c))
        local temp2 = (sum0 + maj) & MASK32

        h = g
        g = f
        f = e
        e = (d + temp1) & MASK32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK32
    end

    -- Add compressed chunk to the running hash value
    H[1] = (H[1] + a) & MASK32
    H[2] = (H[2] + b) & MASK32
    H[3] = (H[3] + c) & MASK32
    H[4] = (H[4] + d) & MASK32
    H[5] = (H[5] + e) & MASK32
    H[6] = (H[6] + f) & MASK32
    H[7] = (H[7] + g) & MASK32
    H[8] = (H[8] + h) & MASK32
end

-- Main SHA256 function (processes whole message or returns chunker)
-- Returns binary digest.
local function sha256(message)
    -- Create an instance (private objects for current calculation)
    local H = {unpack(sha256_H)} -- Copy initial hash values
    local length = 0 -- Message length in bytes
    local tail = "" -- Buffer for incomplete blocks

    local function partial(message_part)
        if message_part then
            length = length + #message_part
            local data = tail .. message_part
            tail = ""
            local num_blocks = (#data - (#data % 64)) / 64
            if num_blocks > 0 then
                local processed_size = num_blocks * 64
                for i = 1, num_blocks do
                    sha256_feed_64(H, sub(data, (i - 1) * 64 + 1, i * 64))
                end
                tail = sub(data, processed_size + 1)
            else
                tail = data
            end
            return partial -- Return chunker function
        else
            -- Finalize hash
            local final_blocks = {}
            local padded_length = length * 8 -- Length in bits

            -- Append padding: a '1' bit, followed by zeros, then 64 bits for length
            local padding = tail .. char(0x80) -- Append 1 bit (as a byte 0x80)
            local zeros_needed = (64 - (#padding % 64)) % 64 -- Zeros to reach 64-byte boundary
            if zeros_needed < 8 then -- Need space for 8-byte length field
                zeros_needed = zeros_needed + 64
            end
            padding = padding .. string_rep(char(0), zeros_needed - 8) -- Append zeros

            -- Append 64-bit message length (big-endian)
            -- Assuming message length fits in Lua number (up to 2^53-1)
            padding = padding .. BIN64_BE(padded_length)

            -- Process final padded blocks
            for i = 1, #padding / 64 do
                 sha256_feed_64(H, sub(padding, (i - 1) * 64 + 1, i * 64))
            end

            -- Output the final binary digest (8 * 4 bytes = 32 bytes)
            local digest_parts = {}
            for i = 1, 8 do
                digest_parts[i] = BIN32_BE(H[i])
            end
            return table_concat(digest_parts)
        end
    end

    if message then
        -- Process message directly if provided as a whole string
        return partial(message)()
    else
        -- Return chunker function for streaming input
        return partial
    end
end

-- HMAC function (uses a hash function that returns binary)
-- Returns binary digest.
local function hmac(hash_func, key, message)
    local block_size -- Block size of the hash function in bytes
    -- Determine block size based on the hash function (SHA256 uses 64 bytes)
    if hash_func == sha256 then
        block_size = 64
    else
        error("Unsupported hash function for HMAC in this module.")
    end

    -- If key is longer than block size, hash it
    if #key > block_size then
        key = hash_func(key) -- hash_func returns binary
    end

    -- Pad key with zeros to block size
    if #key < block_size then
        key = key .. string_rep(char(0), block_size - #key)
    end

    -- Inner and outer padded keys
    local ipad = gsub(key, ".", function(c) return char(byte(c) ~ 0x36) end)
    local opad = gsub(key, ".", function(c) return char(byte(c) ~ 0x5c) end)

    -- Inner hash: H(ipad || message)
    local inner_hash_chunker = hash_func() -- Get chunker for inner hash
    inner_hash_chunker(ipad) -- Feed ipad
    local inner_hash_partial = inner_hash_chunker(message) -- Feed message (or return chunker)

    local function partial(message_part)
        if message_part then
            -- Continue feeding message to the inner hash
            inner_hash_partial(message_part)
            return partial
        else
            -- Finalize inner hash
            local inner_digest_binary = inner_hash_partial() -- Get binary inner digest

            -- Outer hash: H(opad || inner_digest)
            local outer_hash_chunker = hash_func() -- Get chunker for outer hash
            outer_hash_chunker(opad) -- Feed opad
            local outer_digest_binary = outer_hash_chunker(inner_digest_binary)() -- Feed inner digest and finalize

            return outer_digest_binary -- Return binary HMAC digest
        end
    end

    if message then
        -- Process message directly if provided as a whole string
        return partial(message)()
    else
        -- Return chunker function for streaming input
        return partial
    end
end

-- Utility functions (kept for convenience, especially for testing)
local function hex_to_bin(hex_string)
   return (gsub(hex_string, "%x%x",
      function (hh)
         return char(tonumber(hh, 16))
      end
   ))
end

local function bin_to_hex(binary_string)
   return (gsub(binary_string, ".",
      function (c)
         return string_format("%02x", byte(c))
      end
   ))
end

-- Export the functions
return {
    sha256 = sha256,
    hmac = hmac,
    hex_to_bin = hex_to_bin,
    bin_to_hex = bin_to_hex,
}
