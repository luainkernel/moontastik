# Shared helpers for the VM test scripts. Sourced, not executed.

set -euo pipefail

VMTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VMTEST_DIR/../.." && pwd)"
BUILD_DIR="${VMTEST_BUILD_DIR:-$VMTEST_DIR/build}"

# shellcheck source=versions.env
. "$VMTEST_DIR/versions.env"

KERNEL_SRC="$BUILD_DIR/linux-$KERNEL_VERSION"
KERNEL_IMAGE="$KERNEL_SRC/arch/x86/boot/bzImage"
LUNATIK_SRC="${LUNATIK_SRC:-$BUILD_DIR/lunatik}"

log() { printf '\033[1;34m[vmtest]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[vmtest]\033[0m %s\n' "$*" >&2; exit 1; }
