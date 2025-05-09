# ipparse

An object-oriented network packet parser.

`ipparse` is a library designed to parse raw network packet data into an easily accessible, object-oriented structure. It aims to simplify the process of dissecting network protocols from Layer 2 (Ethernet) upwards.

## Features

*   Layered Parsing: Understands common network layers like Ethernet, IP (IPv4/IPv6), TCP, and UDP.
*   Object-Oriented Access: Parsed packet data is presented in a structured way, allowing easy access to header fields (e.g., `packet.ip.src`, `packet.tcp.dst_port`).
*   Extensible: Designed with extensibility in mind for adding new protocol parsers.
*   MoonScript & Lua Friendly: Can be seamlessly used in both MoonScript and Lua projects.

## Installation

`ipparse` is written in MoonScript and needs to be compiled to Lua before use.

### Prerequisites:

MoonScript compiler: Ensure you have `moonc` installed. You can typically install it via LuaRocks: `luarocks install moonscript`.

### Manual Installation from Source

1.  Clone the repository (if you haven't already):
    ```bash
    git clone https://github.com/luainkernel/moontastik/
    cd moontastik/ipparse
    ```

2.  Compile MoonScript to Lua
    The provided `Makefile` handles this. From the root of the `ipparse` directory, run:
    ```bash
    make
    ```
    This will compile all `.moon` files into `.lua` files.

3.  Install the Lua files for Lunatik
    The `Makefile` provides an `install` target that copies the compiled Lua files into Lunatik's directory (typically `/lib/modules/lua/`). You might need superuser privileges for this step:
    ```bash
    sudo make install
    ```

### Alternative Manual Installation (Local Project)

Though intended for use with Lunatik,
ipparse may be used without it.

To use it in a local project, you can:
1.  Create an `ipparse` directory within your project's Lua module path (e.g., `./lib/ipparse` or a directory included in your `LUA_PATH`).
2.  Copy all the generated `.lua` files (preserving their subdirectory structure if `ipparse` has internal modules) into this `ipparse` directory.

`ipparse` is not currently available on LuaRocks.

## Usage

See [examples](./examples/).

