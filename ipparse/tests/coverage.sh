#!/usr/bin/env bash
# Test coverage for ipparse, cumulating LuaJIT and Lua 5.4 runs.
#
# Some code only executes under LuaJIT (lib/pack_compat_lib, FFI backends),
# so coverage must be cumulated across both runtimes. luacov appends its
# counters to an existing stats file, so the suite is run under LuaJIT then
# under Lua 5.4 with the same statsfile, and a single report is generated.
#
# Run from the repository root with both interpreters carrying luacov, plus
# OpenSSL and mbedTLS so the optional FFI crypto backends are exercised
# instead of skipped (tests/ffi_libs.sh builds the matching LD_LIBRARY_PATH):
#
#   nix-shell -p 'luajit.withPackages (p: [p.luacov])' \
#             'lua5_4.withPackages (p: [p.luacov])' \
#             openssl mbedtls \
#             --run 'make -C ipparse coverage-nobuild'
#
# Note: the LuaJIT environment also provides a `lua` symlink pointing at
# LuaJIT, which shadows Lua 5.4's `lua` on PATH. The script therefore probes
# every `lua` on PATH and keeps the one reporting Lua 5.4.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

config=ipparse/.luacov
stats=luacov.stats.out
report=luacov.report.out
test_script=ipparse/tests/run_all.lua

if ! command -v luacov >/dev/null 2>&1; then
  echo "error: luacov not found on PATH" >&2
  exit 1
fi

luajit_bin=
if command -v luajit >/dev/null 2>&1; then
  luajit_bin=$(command -v luajit)
fi

lua54_bin=
IFS=: read -r -a path_dirs <<< "$PATH"
for dir in "${path_dirs[@]}"; do
  candidate="$dir/lua"
  [ -x "$candidate" ] || continue
  if "$candidate" -v 2>&1 | grep -q 'Lua 5\.4'; then
    lua54_bin=$candidate
    break
  fi
done

if [ -z "$luajit_bin" ] && [ -z "$lua54_bin" ]; then
  echo "error: neither luajit nor lua 5.4 found on PATH" >&2
  exit 1
fi

rm -f "$stats" "$report"

# Make the optional FFI crypto backends loadable. ffi_libs.sh prints the
# relevant library dirs (and warns on stderr when a library is missing); if
# none are found we keep going and the backends' tests skip themselves.
ffi_ld_path=$("$script_dir/ffi_libs.sh")
if [ -n "$ffi_ld_path" ]; then
  export LD_LIBRARY_PATH="${ffi_ld_path}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

run_suite() {
  local bin=$1 name=$2
  echo "==> Running test suite under $name ($bin)" >&2
  if ! LUA_PATH="./?.lua;./?/init.lua;;" "$bin" -lluacov.runner \
      -e "require('luacov.runner').init('$config')" "$test_script" 1>&2; then
    echo "error: test suite failed under $name" >&2
    exit 1
  fi
}

if [ -n "$luajit_bin" ]; then
  run_suite "$luajit_bin" LuaJIT
fi
if [ -n "$lua54_bin" ]; then
  run_suite "$lua54_bin" "Lua 5.4"
fi

luacov -c "$config" >&2

sed -n '/^Summary$/,$p' "$report"

total=$(awk '/^Total[[:space:]]/{print $NF}' "$report" | tail -n 1)
total=${total%\%}
echo "COVERAGE_TOTAL=$total"
