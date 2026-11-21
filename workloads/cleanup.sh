#!/usr/bin/env bash
# cleanup.sh - remove files left in the sandbox by the attacks and the noise.
#
#   ./workloads/cleanup.sh          attack + noise files
#   ./workloads/cleanup.sh --all    also the cached benign inputs (~1 GB of RAM)
#
# Run this BETWEEN runs, while no consumer is running: deleting hundreds of
# files is a burst of unlink events that the detector would (correctly)
# flag as ransomware.
set -euo pipefail
source "$(dirname "$0")/common.sh"

case "$SANDBOX" in /tmp/edr_sandbox*) ;; *) die "refusing to clean '$SANDBOX'" ;; esac
rm -rf "${SANDBOX:?}/attacks" "${SANDBOX:?}/noise"
[[ "${1:-}" == "--all" ]] && rm -rf "${SANDBOX:?}/benign"
exit 0
