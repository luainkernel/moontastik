#!/bin/bash
# Parse a real QUIC packet from a PCAP/PCAPNG capture.
#
# Usage:
#   ./examples/parse_real_quic.sh /path/to/capture.pcapng
#   ./examples/parse_real_quic.sh /path/to/capture.pcap

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PCAP_FILE="${1:-${PROJECT_ROOT}/quic.pcapng}"

if [ ! -f "${PCAP_FILE}" ]; then
  echo "ERROR: capture file not found: ${PCAP_FILE}"
  exit 1
fi

LUA_PATH="${PROJECT_ROOT}/../?.lua;${PROJECT_ROOT}/../?/init.lua;;" \
  luajit "${SCRIPT_DIR}/parse_real_quic.lua" "${PCAP_FILE}"
