#!/usr/bin/env bash
# Runs INSIDE the VM (root, host filesystem mounted with a writable overlay).
# Installs lunatik + ipparse into the overlay, then runs the full test suite.

. "$(dirname "$0")/lib.sh"

KREL="$(cat "$BUILD_DIR/kernelrelease")"
[ "$(uname -r)" = "$KREL" ] || die "VM kernel $(uname -r) != expected $KREL"

log "Installing lunatik modules + scripts into the overlay…"
# LUA_PATH/LUA_CPATH (make variables): where lunatik installs its modules and
# eBPF loader. Their defaults are derived from package.path/package.cpath,
# which point into the read-only /nix/store; use the writable overlay instead.
# Upstream master derives both from $(LUA) (default lua5.5), hence passing
# LUA explicitly as well.
GUEST_LUA_DIR=/usr/local/share/lua/5.4
GUEST_LUA_CPATH=/usr/local/lib/lua/5.4
# cd rather than make -C: lunatik's Makefile uses $(PWD)
# INSTALL: /lib/modules is a 9p mount mapped to the host user; chown to
# root is impossible there (and irrelevant for tests).
(cd "$LUNATIK_SRC" && make install \
  LUA=lua5.4 \
  KERNEL_RELEASE="$KREL" \
  MODULES_BUILD_PATH="$KERNEL_SRC" \
  LUA_PATH="$GUEST_LUA_DIR" \
  LUA_CPATH="$GUEST_LUA_CPATH" \
  INSTALL="install" \
  >/dev/null)
depmod "$KREL"

# The installed CLI has a #!/usr/bin/lua5.4 shebang (absent here) and needs
# its modules on lua's package.path: shim it.
mkdir -p /usr/local/bin
cat > /usr/local/bin/lunatik <<EOF
#!$(command -v bash)
export LUA_PATH="$GUEST_LUA_DIR/?.lua;$GUEST_LUA_DIR/?/init.lua;/lib/modules/lua/?.lua;/lib/modules/lua/?/init.lua;;"
export LUA_CPATH="$GUEST_LUA_CPATH/?.so;;"
exec $(command -v lua5.4) /usr/local/sbin/lunatik "\$@"
EOF
chmod +x /usr/local/bin/lunatik
export PATH="/usr/local/bin:$PATH"

log "Installing ipparse…"
# -nobuild: the source tree is mounted read-only; .lua files were compiled
# on the host before boot.
make -C "$REPO_ROOT/ipparse" install-nobuild >/dev/null

log "Loading lunatik…"
modprobe lunatik

rc=0

log "Running userspace test suite (LuaJIT)…"
make -C "$REPO_ROOT/ipparse" test-nobuild || rc=1

log "Running kernel test suite (lunatik)…"
make -C "$REPO_ROOT/ipparse" test-lunatik-run || rc=1

if [ "${VMTEST_BYTECODE:-1}" != "0" ]; then
  if [ -x "$LUNATIK_SRC/bin/lunatic" ]; then
    log "Reinstalling ipparse as bytecode…"
    if make -C "$REPO_ROOT/ipparse" install-nobuild BYTECODE=1 \
      LUNATIC="$LUNATIK_SRC/bin/lunatic" >/dev/null; then
      log "Running kernel test suite (lunatik, bytecode)…"
      make -C "$REPO_ROOT/ipparse" test-lunatik-run || rc=1
    else
      rc=1
    fi
  else
    log "lunatic not available: bytecode pass skipped"
  fi
fi

if [ "$rc" -ne 0 ]; then
  log "FAILURES — last kernel messages:"
  dmesg | tail -50 >&2
fi
exit "$rc"
