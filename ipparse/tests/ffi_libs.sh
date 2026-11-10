#!/usr/bin/env bash
# Print a colon-separated search path exposing the libraries the FFI crypto
# backends load with ffi.load(): libcrypto.so (OpenSSL) and libmbedcrypto.so
# (mbedTLS). Both are optional: when a library is missing the tests that need
# it skip themselves.
#
# Inside `nix-shell -p openssl mbedtls`, NIX_LDFLAGS already lists the store
# lib directories as `-L/nix/store/.../lib`; we keep only existing directories
# and probe for the libraries instead of hard-coding store hashes.
#
# Also usable with `--check`, which exits non-zero when either library is
# missing (used to warn without failing the caller).
set -euo pipefail

declare -A seen=()
dirs=()

add_dir() {
  local dir=$1
  [ -n "$dir" ] || return 0
  [ -d "$dir" ] || return 0
  [ -n "${seen[$dir]:-}" ] && return 0
  seen[$dir]=1
  dirs+=("$dir")
}

add_ldflags() {
  local token
  for token in ${1:-}; do
    case $token in
      -L*) add_dir "${token#-L}" ;;
    esac
  done
}

if [ -n "${LD_LIBRARY_PATH:-}" ]; then
  IFS=: read -r -a current <<< "$LD_LIBRARY_PATH"
  for dir in "${current[@]}"; do
    add_dir "$dir"
  done
fi

add_ldflags "${NIX_LDFLAGS:-}"

# Fallback: a nix-shell package's runtime libraries live in ../lib next to its
# binary on PATH.
for tool in openssl mbedtls; do
  bin=$(command -v "$tool" 2>/dev/null || true)
  if [ -n "$bin" ]; then
    add_dir "$(cd -- "$(dirname -- "$bin")/../lib" 2>/dev/null && pwd || true)"
  fi
done

has_lib() {
  local soname=$1 dir
  for dir in "${dirs[@]+"${dirs[@]}"}"; do
    [ -e "$dir/$soname" ] && return 0
  done
  return 1
}

path=
[ "${#dirs[@]}" -eq 0 ] || path=$(IFS=:; echo "${dirs[*]}")
printf '%s\n' "$path"

missing=
has_lib libcrypto.so || missing=libcrypto.so
has_lib libmbedcrypto.so || missing="${missing:+$missing }libmbedcrypto.so"

if [ -n "$missing" ]; then
  echo "warning: FFI crypto libraries not found (${missing}); those tests will be skipped" >&2
  if [ "${1:-}" = "--check" ]; then
    exit 1
  fi
fi
