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

## Releasing

A `vX.Y.Z` tag (SemVer, e.g. `v2.0.0`) triggers `.github/workflows/main.yml`:
the GitHub release with `moontastik_lua.zip`, then the LuaRocks publication of
`ipparse` by the `luarocks` job. Increment MAJOR for an incompatible API
change, MINOR for a backward-compatible addition, and PATCH for a fix. The
legacy two-part forms `vX.Y` and `vX.Y-Z` are still accepted.

1. Create `ipparse-X.Y.Z-1.rockspec` at the repository root (`v2.0.0` →
   `ipparse-2.0.0-1.rockspec`), with `version = "X.Y.Z-1"` and
   `source.url = "https://github.com/luainkernel/moontastik/archive/refs/tags/vX.Y.Z.tar.gz"`.
   Do not add an `md5` with that URL: the tag archive only exists once the tag
   is pushed, so its checksum cannot be known beforehand.
2. Regenerate the API documentation (`make -C ipparse doc`) and commit
   everything. The pre-commit hook (enabled by `make hooks`, see
   [Development](#development)) refuses a rockspec bump when the committed
   documentation is stale.
3. `git tag vX.Y.Z && git push --tags`
4. Once: create the `LUAROCKS_API_KEY` secret (Settings → Secrets and
   variables → Actions) with a LuaRocks API key; without it the `luarocks` job
   fails explicitly.
