#!/usr/bin/env bash
# noise.sh - background event noise at roughly N events per second.
#
#   ./workloads/noise.sh --rate <events_per_sec> --duration 30 [--workers N]
#
# Thin wrapper around build/edr_noise (see workloads/edr_noise.c). Check the
# real rate with evdump: emitted / duration.
set -euo pipefail
source "$(dirname "$0")/common.sh"
need_bin edr_noise
mkdir -p "$SANDBOX"
exec "$BIN/edr_noise" --sandbox "$SANDBOX" "$@"
