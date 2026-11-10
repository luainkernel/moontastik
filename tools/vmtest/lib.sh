# Shared helpers for the VM test scripts. Sourced, not executed.

set -euo pipefail

VMTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VMTEST_DIR/../.." && pwd)"
# Absolute paths: the guest re-sources this file and must not resolve them
# relative to its own cwd (which differs from the host's).
BUILD_DIR="$(realpath -m -- "${VMTEST_BUILD_DIR:-$VMTEST_DIR/build}")"

# shellcheck source=versions.env
. "$VMTEST_DIR/versions.env"

KERNEL_SRC="$BUILD_DIR/linux-$KERNEL_VERSION"
KERNEL_IMAGE="$KERNEL_SRC/arch/x86/boot/bzImage"
# Remember whether LUNATIK_SRC came from the environment (user-provided
# checkout, never altered) or is the harness-managed cache under BUILD_DIR.
LUNATIK_SRC_USER="${LUNATIK_SRC:-}"
LUNATIK_SRC="$(realpath -m -- "${LUNATIK_SRC:-$BUILD_DIR/lunatik}")"

log() { printf '\033[1;34m[vmtest]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[vmtest]\033[0m %s\n' "$*" >&2; exit 1; }
