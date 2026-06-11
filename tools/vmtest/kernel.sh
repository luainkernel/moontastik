#!/usr/bin/env bash
# Downloads and builds the pinned LTS kernel for the test VM (idempotent).
# The build is done with virtme-ng's defconfig (tuned for fast VM boot),
# plus the options Lunatik needs (kernel.fragment).

. "$(dirname "$0")/lib.sh"

if [ -e "$KERNEL_IMAGE" ] && [ -e "$KERNEL_SRC/.vmtest-fragment-hash" ] \
   && [ "$(cat "$KERNEL_SRC/.vmtest-fragment-hash")" = "$(sha256sum "$VMTEST_DIR/kernel.fragment" | cut -d' ' -f1)" ]; then
  log "Kernel $KERNEL_VERSION already built: $KERNEL_IMAGE"
  exit 0
fi

mkdir -p "$BUILD_DIR"

if [ ! -d "$KERNEL_SRC" ]; then
  major="${KERNEL_VERSION%%.*}"
  url="https://cdn.kernel.org/pub/linux/kernel/v${major}.x/linux-$KERNEL_VERSION.tar.xz"
  log "Downloading $url…"
  curl -fL --retry 3 -o "$BUILD_DIR/linux-$KERNEL_VERSION.tar.xz" "$url"
  log "Extracting…"
  tar -C "$BUILD_DIR" -xf "$BUILD_DIR/linux-$KERNEL_VERSION.tar.xz"
  rm "$BUILD_DIR/linux-$KERNEL_VERSION.tar.xz"
fi

cd "$KERNEL_SRC"
log "Generating virtme-ng config (+ lunatik fragment)…"
vng --kconfig --config "$VMTEST_DIR/kernel.fragment"

# vng's template enables the system trusted keyring; building it links the
# host tool certs/extract-cert against the ambient openssl, which clashes
# with the pinned Nix toolchain (mixed glibc). Not needed for tests.
scripts/config --disable SYSTEM_TRUSTED_KEYRING \
               --disable SECONDARY_TRUSTED_KEYRING \
               --disable SYSTEM_BLACKLIST_KEYRING \
               --disable MODULE_SIG
make olddefconfig
if grep -q '^CONFIG_SYSTEM_TRUSTED_KEYRING=y' .config; then
  die "SYSTEM_TRUSTED_KEYRING still enabled (selected by another option)"
fi

log "Building kernel $KERNEL_VERSION…"
make -j"$(nproc)" bzImage modules

[ -e "$KERNEL_IMAGE" ] || die "kernel build did not produce $KERNEL_IMAGE"
sha256sum "$VMTEST_DIR/kernel.fragment" | cut -d' ' -f1 > "$KERNEL_SRC/.vmtest-fragment-hash"
log "Kernel ready: $KERNEL_IMAGE"
