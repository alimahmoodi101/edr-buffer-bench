#!/usr/bin/env bash
# run_attacks.sh - inject attacks spread evenly over a time window and write
# the ground truth to <out>/injections.csv (docs/CONTRACT.md section 3).
#
#   sudo ./workloads/run_attacks.sh --duration 30 --count 3 --out results/<run>/
#
# --count N runs each of the three attacks N times (3N injections in total),
# interleaved: ransomware, forkstorm, privesc, ransomware, ...
# Run it with sudo so that setuid(0) really succeeds (without root it still
# makes the syscall, so the events look the same, but it is less realistic).
set -euo pipefail
source "$(dirname "$0")/common.sh"

duration=30 count=3 out="" files=64 children=128

usage() {
	cat >&2 <<EOF
usage: sudo $0 --duration SEC --count N --out DIR [--files N] [--children N]
  --duration SEC  spread the attacks over this many seconds (default 30)
  --count N       how many times to run EACH attack (default 3)
  --out DIR       run folder; injections.csv is written here
  --files N       ransomware files per attack (default 64; detector needs 50)
  --children N    fork storm children (default 128; detector needs 100)
EOF
	exit 1
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration) duration="$2"; shift 2 ;;
	--count)    count="$2"; shift 2 ;;
	--out)      out="$2"; shift 2 ;;
	--files)    files="$2"; shift 2 ;;
	--children) children="$2"; shift 2 ;;
	-h|--help)  usage ;;
	*) echo "unknown option: $1" >&2; usage ;;
	esac
done
[[ -n "$out" ]] || usage
need_bin edr_attack
[[ $EUID -eq 0 ]] || log "warning: not root, setuid(0) will fail (event is still traced)"

mkdir -p "$out" "$SANDBOX"
csv="$out/injections.csv"
echo "attack,start_ns,end_ns,tgid" > "$csv"

attacks=()
for ((r = 0; r < count; r++)); do attacks+=(ransomware forkstorm privesc); done
total=${#attacks[@]}

# attack i starts at t0 + (i + 0.5) * slot, so they are evenly spaced and
# none sits right at the edge of the window
dur_us=$(awk -v d="$duration" 'BEGIN { printf "%d", d * 1000000 }')
slot_us=$(( dur_us / total ))
t0=$(now_us)

for ((i = 0; i < total; i++)); do
	sleep_until_us $(( t0 + i * slot_us + slot_us / 2 ))
	"$BIN/edr_attack" "${attacks[i]}" --files "$files" --children "$children" \
		--sandbox "$SANDBOX" >> "$csv"
done
sleep_until_us $(( t0 + dur_us ))

give_back "$out" "$SANDBOX"
log "$total attacks written to $csv"
