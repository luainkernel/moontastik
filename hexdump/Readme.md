# Hexdump

Hexdump is a kernel script that uses the lunatik netfilter or xdp library to dump packets content.

## Installation

We assume a Debian system. Adapt to your case.

Install [lunatik](https://github.com/luainkernel/lunatik).

Install [MoonScript](https://moonscript.org):

```sh
sudo apt install luarocks && sudo luarocks install moonscript  # build dependency
```

Install [ipparse](https://github.com/luainkernel/moontastik/tree/master/ipparse):

```sh
git clone https://github.com/luainkernel/moontastik
cd moontastik/ipparse
make && sudo make install
cd ..
```

Install hexdump:

Choose between XDP mode and netfilter mode, by defining appropriate variables
in `hook.moon`. Both may be used at the same time, but it's redundant.
XDP mode is faster, but needs to load an helper.

```sh
cd hexdump
sudo make install      # installs Lua files to module directory
```


### XDP mode

Compile `xdp.o`:

```sh
make xdp.o
```

## Usage

```sh
sudo lunatik start hexdump/hook false                # runs the Lua kernel script
sudo xdp-loader load -m skb eth0 xdp.o               # if using XDP: replace eth0 by your interface.
sudo journalctl -ft kernel                           # or use dmesg
sudo xdp-loader unload eth0 --all                    # unloads the XDP helper
sudo lunatik stop snihook/main                       # stops the Lua kernel script
```

