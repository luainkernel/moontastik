#!/usr/bin/env bash
# Clones (pinned ref) and builds Lunatik against the pinned kernel.
# Set LUNATIK_SRC to use a local checkout instead of the pinned clone.

. "$(dirname "$0")/lib.sh"

[ -e "$KERNEL_IMAGE" ] || die "kernel not built yet — run kernel.sh first"

if [ ! -d "$LUNATIK_SRC" ]; then
  log "Cloning $LUNATIK_REPO@$LUNATIK_REF…"
  git clone --depth 1 --branch "$LUNATIK_REF" --recurse-submodules \
    "$LUNATIK_REPO" "$LUNATIK_SRC"
fi

KREL="$(make -s -C "$KERNEL_SRC" kernelrelease)"
log "Building lunatik against $KREL ($KERNEL_SRC)…"
# cd rather than make -C: lunatik's Makefile passes M=$(PWD) to Kbuild,
# and PWD is the caller's directory unless we actually chdir.
(cd "$LUNATIK_SRC" && make \
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
