#!/usr/bin/env bash
# Entry point: builds everything (cached) and runs the full test suite in
# a virtme-ng microVM on the pinned kernel. Exit code = test result.
#
# Usage:
#   tools/vmtest/run.sh              # full run (kernel + lunatik + tests)
#   tools/vmtest/run.sh --smoke      # just boot the VM and check the kernel
#   tools/vmtest/run.sh --lunatik    # run lunatik's own test suite
#   tools/vmtest/run.sh --all        # every kernel in KERNEL_VERSIONS
#
# Requires the dev shell:  nix develop ./tools/vmtest

. "$(dirname "$0")/lib.sh"

usage() {
  cat >&2 <<EOF
Usage: $0 [--all] [--lunatik] [--smoke]
  --all      run the full suite on every kernel in KERNEL_VERSIONS
  --lunatik  run lunatik's own test suite instead of the ipparse one
  --smoke    only boot the VM and check the kernel version
EOF
}

OPT_ALL=0 OPT_LUNATIK=0 OPT_SMOKE=0
for arg in "$@"; do
  case "$arg" in
    --all) OPT_ALL=1 ;;
    --lunatik) OPT_LUNATIK=1 ;;
    --smoke) OPT_SMOKE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $arg" ;;
  esac
done

if [ "$OPT_ALL" -eq 1 ]; then
  child_args=()
  [ "$OPT_LUNATIK" -eq 1 ] && child_args+=(--lunatik)
  [ "$OPT_SMOKE" -eq 1 ] && child_args+=(--smoke)

  versions=() rcs=()
  overall=0
  for v in $KERNEL_VERSIONS; do
    log "=== kernel $v ==="
    if KERNEL_VERSION="$v" "$0" ${child_args[@]+"${child_args[@]}"}; then
      rc=0
    else
      rc=$?
    fi
    versions+=("$v"); rcs+=("$rc")
    [ "$rc" -eq 0 ] || overall=1
  done

  log "Summary (version -> rc):"
  for i in "${!versions[@]}"; do
    printf '  %-10s %s\n' "${versions[$i]}" "${rcs[$i]}" >&2
  done
  exit "$overall"
fi

"$VMTEST_DIR/ensure-vng.sh"
export PATH="$VMTEST_DIR/.venv/bin:$PATH"

"$VMTEST_DIR/kernel.sh"

# Runs a command inside the VM.
#
# The guest shares the host filesystem but not the environment: on NixOS
# nothing lives in /usr/bin, so the dev-shell PATH is re-exported and bash
# addressed by absolute (nix-store) path. vng's own exit-code propagation
# relies on virtio-serial script ports that are not always available
# (no udev in the minimal guest), so the guest writes its output and exit
# code into a shared writable directory instead.
BASH_ABS="$(command -v bash)"
# Must live OUTSIDE the repository: nested inside --rodir it would be
# shadowed by the read-only mount. Default to a fresh directory per run so
# concurrent invocations (including one per kernel under --all) do not
# clobber each other's out/rc/console.log.
if [ -n "${VMTEST_RW_DIR:-}" ]; then
  RW_DIR="$VMTEST_RW_DIR"
  RW_DIR_OWNED=0
else
  RW_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vmtest-rw.XXXXXX")"
  RW_DIR_OWNED=1
  # Keep the console log around on failure (the error message points to it).
  trap 'st=$?; if [ "$st" -eq 0 ] && [ "$RW_DIR_OWNED" -eq 1 ]; then rm -rf "$RW_DIR"; fi' EXIT
fi
# vng bind-mounts the kernel's module dir read-only over /lib/modules;
# lunatik and ipparse need to install there, so mount a writable 9p
# (host-backed, reusable across boots) on top instead. GUEST_MODULES_DIR
# is per kernel version (see lib.sh).
mkdir -p "$GUEST_MODULES_DIR"

in_vm() {
  rm -rf "$RW_DIR"; mkdir -p "$RW_DIR"
  local wrapper="$RW_DIR/cmd.sh"
  {
    printf '#!%s\n' "$BASH_ABS"
    printf 'export PATH=%q\n' "$PATH"
    # The guest does not inherit the environment (only PATH above): export
    # what lib.sh needs so it does not fall back to the build dir inside the
    # (read-only) repo, to the pinned lunatik clone, or to the default kernel
    # when the host used an override.
    printf 'export VMTEST_BUILD_DIR=%q\n' "$BUILD_DIR"
    printf 'export LUNATIK_SRC=%q\n' "$LUNATIK_SRC"
    printf 'export KERNEL_VERSION=%q\n' "$KERNEL_VERSION"
    printf 'export VMTEST_BYTECODE=%q\n' "${VMTEST_BYTECODE:-1}"
    printf '( %s ) > %q/out 2>&1\n' "$*" "$RW_DIR"
    printf 'echo $? > %q/rc\n' "$RW_DIR"
  } > "$wrapper"
  chmod +x "$wrapper"
  vng --verbose --run "$KERNEL_IMAGE" --user root --cpus "$(nproc)" --memory 2G \
    --rodir "$REPO_ROOT" --rwdir "$RW_DIR" \
    --rwdir "/lib/modules=$GUEST_MODULES_DIR" \
    -- "$BASH_ABS" "$wrapper" > "$RW_DIR/console.log" 2>&1 || true
  cat "$RW_DIR/out" 2>/dev/null
  rc="$(cat "$RW_DIR/rc" 2>/dev/null)"
  [ -n "$rc" ] || { sed -n '$p' "$RW_DIR/console.log" >&2; die "VM did not run the guest command (see $RW_DIR/console.log)"; }
  return "$rc"
}

if [ "$OPT_SMOKE" -eq 1 ]; then
  log "Smoke test: booting VM…"
  got="$(in_vm uname -r)" || die "guest command failed: $got"
  log "VM kernel: $got"
  case "$got" in "$KERNEL_VERSION"*) log "Smoke test OK";; *) die "unexpected kernel: $got";; esac
  if in_vm "exit 7" >/dev/null; then
    die "exit-code round-trip broken"
  fi
  log "Exit-code round-trip OK"
  exit 0
fi

"$VMTEST_DIR/build-lunatik.sh"

if [ "$OPT_LUNATIK" -eq 1 ]; then
  guest_script="guest-lunatik.sh"
else
  guest_script="guest-test.sh"
  log "Compiling ipparse (.moon → .lua) on the host…"
  make -C "$REPO_ROOT/ipparse" all >/dev/null
fi

log "Booting VM and running the test suite…"
if in_vm "bash '$VMTEST_DIR/$guest_script'"; then
  log "All tests passed in VM"
else
  rc=$?
  log "Test suite FAILED (rc=$rc) — console log: $RW_DIR/console.log"
  exit "$rc"
fi
