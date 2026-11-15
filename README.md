# Moontastik

MoonScript collection for Lunatik

## ipparse

[ipparse](./ipparse/) is a library to parse network packets (as presented on Lunatik's socket buffers).

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/luainkernel/moontastik)

## Development

Run `make hooks` once after cloning: it points `core.hooksPath` at the
versioned `.githooks/`, whose pre-commit hook refuses an `ipparse-*.rockspec`
bump when the committed API documentation is stale.
Docs live in `ipparse/doc/` and are committed; regenerate them with
`make -C ipparse doc` (needs LDoc, e.g. `nix-shell -p luajitPackages.ldoc`).
