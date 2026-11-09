#!/usr/bin/env bash
# Runs INSIDE the VM (root, host filesystem mounted with a writable overlay).
# Installs lunatik (modules, scripts and tests) and runs lunatik's own suite.

. "$(dirname "$0")/lib.sh"

KREL="$(cat "$KERNELREL_FILE")"
[ "$(uname -r)" = "$KREL" ] || die "VM kernel $(uname -r) != expected $KREL"

log "Installing lunatik modules, scripts and tests into the overlay…"
G=/usr/local/share/lua/5.5
CPATH_DIR=/usr/local/lib/lua/5.5
# Drop scripts installed by a previous (possibly other kernel) run so stale
# files cannot shadow the freshly installed ones.
rm -rf /lib/modules/lua
# cd rather than make -C: lunatik's Makefile uses $(PWD)
# INSTALL: /lib/modules is a 9p mount mapped to the host user; chown to
# root is impossible there (and irrelevant for tests).
(cd "$LUNATIK_SRC" && make install tests_install \
  KERNEL_RELEASE="$KREL" \
  MODULES_BUILD_PATH="$KERNEL_SRC" \
  LUA=lua5.5 \
  LUA_PATH="$G" \
  LUA_CPATH="$CPATH_DIR" \
  INSTALL="install" \
  >/dev/null)
depmod "$KREL"

# The installed CLI has a #!/usr/bin/lua5.5 shebang (absent here) and needs
# its modules on lua's package.path/package.cpath: shim it.
mkdir -p /usr/local/bin "$CPATH_DIR"
cat > /usr/local/bin/lunatik <<EOF
#!$(command -v bash)
export LUA_PATH="$G/?.lua;$G/?/init.lua;/lib/modules/lua/?.lua;/lib/modules/lua/?/init.lua;;"
export LUA_CPATH="$CPATH_DIR/?.so;;"
exec $(command -v lua5.5) /usr/local/sbin/lunatik "\$@"
EOF
chmod +x /usr/local/bin/lunatik
export PATH="/usr/local/bin:$PATH"

log "Running lunatik test suite…"
lunatik test
