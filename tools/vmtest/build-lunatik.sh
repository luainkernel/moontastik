#!/usr/bin/env bash
# Clones (pinned ref) and builds Lunatik against the pinned kernel.
# Set LUNATIK_SRC to use a local checkout instead of the pinned clone.

. "$(dirname "$0")/lib.sh"

[ -e "$KERNEL_IMAGE" ] || die "kernel not built yet — run kernel.sh first"

# LUNATIK_REF is a tag by default; verify it still points at LUNATIK_COMMIT.
# LUNATIK_COMMIT is empty when testing an unpinned reference (master, or an
# arbitrary ref supplied by the CI workflow).
clone_pinned() {
  log "Cloning $LUNATIK_REPO@$LUNATIK_REF…"
  rm -rf "$LUNATIK_SRC"
  git clone --depth 1 --branch "$LUNATIK_REF" --recurse-submodules \
    "$LUNATIK_REPO" "$LUNATIK_SRC"
  if [ -n "${LUNATIK_COMMIT:-}" ]; then
    head="$(git -C "$LUNATIK_SRC" rev-parse HEAD)"
    if [ "$head" != "$LUNATIK_COMMIT" ]; then
      die "$LUNATIK_REF resolved to $head, expected pinned commit $LUNATIK_COMMIT (was the tag moved?)"
    fi
  fi
}

lunatik_head() {
  git -C "$LUNATIK_SRC" rev-parse HEAD 2>/dev/null || echo unknown
}

if [ ! -d "$LUNATIK_SRC" ]; then
  # An absent directory is cloned even when LUNATIK_SRC was named explicitly.
  clone_pinned
elif [ -z "$LUNATIK_SRC_USER" ]; then
  # Harness-managed cache: never trust a stale checkout silently.
  if [ -n "${LUNATIK_COMMIT:-}" ] && [ "$(lunatik_head)" != "$LUNATIK_COMMIT" ]; then
    log "Cached Lunatik checkout is at $(lunatik_head), expected $LUNATIK_COMMIT — re-cloning…"
    clone_pinned
  fi
else
  head="$(lunatik_head)"
  if [ -n "${LUNATIK_COMMIT:-}" ] && [ "$head" != "$LUNATIK_COMMIT" ]; then
    log "WARNING: user-provided LUNATIK_SRC $LUNATIK_SRC is at $head, not the pinned $LUNATIK_COMMIT — using it as-is"
  fi
fi

KREL="$(make -s -C "$KERNEL_SRC" kernelrelease)"
log "Building lunatik against $KREL ($KERNEL_SRC)…"
# cd rather than make -C: lunatik's Makefile passes M=$(PWD) to Kbuild,
# and PWD is the caller's directory unless we actually chdir.
# Upstream v5.1 defaults LUA to lua5.5 (bundled kernel Lua). LUA here only
# drives host-side code generation and the CLI, so use the 5.4 toolchain
# already required by CI; the kernel module still embeds Lua 5.5.
(cd "$LUNATIK_SRC" && make \
  LUA="${LUNATIK_LUA:-lua5.4}" \
  KERNEL_RELEASE="$KREL" \
  MODULES_BUILD_PATH="$KERNEL_SRC" \
  -j"$(nproc)")

echo "$KREL" > "$BUILD_DIR/kernelrelease"

# Pre-populate the guest /lib/modules 9p mount with the kernel's module
# metadata (modules.builtin & co), so depmod/modprobe work in the VM.
GUEST_MODULES_DIR="$BUILD_DIR/guest-modules"
mkdir -p "$GUEST_MODULES_DIR"
make -C "$KERNEL_SRC" modules_install \
  INSTALL_MOD_PATH="$BUILD_DIR/guest-modules-staging" >/dev/null
rm -rf "$GUEST_MODULES_DIR/$KREL"
mv "$BUILD_DIR/guest-modules-staging/lib/modules/$KREL" "$GUEST_MODULES_DIR/$KREL"
rm -rf "$BUILD_DIR/guest-modules-staging"
log "Lunatik modules built ($(find "$LUNATIK_SRC" -name '*.ko' | wc -l) .ko files)"
