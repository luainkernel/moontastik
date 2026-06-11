#!/usr/bin/env bash
# Entry point: builds everything (cached) and runs the full test suite in
# a virtme-ng microVM on the pinned kernel. Exit code = test result.
#
# Usage:
#   tools/vmtest/run.sh           # full run (kernel + lunatik + tests)
#   tools/vmtest/run.sh --smoke   # just boot the VM and check the kernel
#
# Requires the dev shell:  nix develop ./tools/vmtest

. "$(dirname "$0")/lib.sh"

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
# shadowed by the read-only mount.
RW_DIR="${VMTEST_RW_DIR:-${TMPDIR:-/tmp}/vmtest-rw}"
# vng bind-mounts the kernel's module dir read-only over /lib/modules;
# lunatik and ipparse need to install there, so mount a writable 9p
# (host-backed, reusable across boots) on top instead.
GUEST_MODULES_DIR="$BUILD_DIR/guest-modules"
mkdir -p "$GUEST_MODULES_DIR"

in_vm() {
  rm -rf "$RW_DIR"; mkdir -p "$RW_DIR"
  local wrapper="$RW_DIR/cmd.sh"
  {
    printf '#!%s\n' "$BASH_ABS"
    printf 'export PATH=%q\n' "$PATH"
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

if [ "${1:-}" = "--smoke" ]; then
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

log "Compiling ipparse (.moon → .lua) on the host…"
make -C "$REPO_ROOT/ipparse" all >/dev/null

log "Booting VM and running the test suite…"
if in_vm "bash '$VMTEST_DIR/guest-test.sh'"; then
  log "All tests passed in VM"
else
  rc=$?
  log "Test suite FAILED (rc=$rc) — console log: $RW_DIR/console.log"
  exit "$rc"
fi
