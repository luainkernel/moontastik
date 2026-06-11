#!/usr/bin/env bash
# Installs virtme-ng in a local venv (idempotent).
# virtme-ng is not packaged in nixpkgs; pip gives us the same version
# locally and in CI.

. "$(dirname "$0")/lib.sh"

VENV="$VMTEST_DIR/.venv"

if [ -x "$VENV/bin/vng" ]; then
  log "virtme-ng already installed: $("$VENV/bin/vng" --version 2>/dev/null || true)"
  exit 0
fi

log "Creating venv and installing virtme-ng…"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet virtme-ng
log "Installed: $("$VENV/bin/vng" --version)"
