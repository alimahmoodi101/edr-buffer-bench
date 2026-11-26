#!/usr/bin/env bash
#run_bench.sh - Part 5. Runs every design x rate x cpu load x repeat and saves
#each run in its own folder (see docs/CONTRACT.md section 3).
#
#  sudo ./bench/run_bench.sh --quick          small test, takes a few minutes
#  sudo ./bench/run_bench.sh                  the full thing
#  sudo ./bench/run_bench.sh --list           only show how many runs and how long
#  sudo ./bench/run_bench.sh --no-overhead    skip the overhead runs
#  sudo ./bench/run_bench.sh --only-overhead  only the overhead runs
#
#you can stop it any time and start it again, finished runs are skipped
#run it inside tmux so it keeps going if your terminal closes
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

#---- settings (change here or set them from outside, e.g. REPS=2 sudo -E ...) ----
VARIANTS="${VARIANTS:-fifo percpu prio priosamp}"   #priosamp = prio + adaptive sampling
RATES="${RATES:-50000 200000 0}"                    #noise events per second, 0 = as fast as possible
LOADS="${LOADS:-0 100 150}"                         #cpu load, can also have 50 and llm
REPS="${REPS:-5}"
MEM="${MEM:-256K}"                                  #same total buffer memory for every design
DURATION="${DURATION:-30}"                          #seconds the consumer runs
WARMUP="${WARMUP:-3}"                               #seconds of noise before the first attack
ATTACK_WINDOW="${ATTACK_WINDOW:-20}"                #attacks are spread over this many seconds
COUNT="${COUNT:-3}"                                 #each attack is run this many times
OUT="${OUT:-results}"

mode=all
quick=0
list_only=0
for a in "$@"; do
	case "$a" in
	--quick) quick=1 ;;
	--list) list_only=1 ;;
	--no-overhead) mode=main ;;
	--only-overhead) mode=overhead ;;
	-h|--help) sed -n 2,12p "$0"; exit 0 ;;
	*) echo "unknown option $a"; exit 1 ;;
	esac
done

if [[ $quick -eq 1 ]]; then
	RATES="50000 0"
	LOADS="0 150"
	REPS=1
	DURATION=12
	WARMUP=2
	ATTACK_WINDOW=6
	OUT="/tmp/edr_quick_results"
fi

log() { echo "[$(date +%H:%M:%S)] $*"; }

#---- checks ----
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ -x build/edr_consumer ]] || { echo "build/edr_consumer missing, run make first"; exit 1; }
[[ -x build/edr_attack && -x build/edr_noise ]] || { echo "workload binaries missing, run make first"; exit 1; }
command -v stress-ng >/dev/null || { echo "stress-ng missing"; exit 1; }
[[ $(nproc) -eq 4 ]] || log "warning: this machine has $(nproc) cpus, the project says 4"
if [[ " $LOADS " == *" llm "* ]]; then
	command -v llama-bench >/dev/null || { echo "llm load needs llama-bench (see workloads/README.md)"; exit 1; }
fi

mkdir -p "$OUT"
FAILED="$OUT/failed.log"

#---- list of all runs ----
runs=()
for v in $VARIANTS; do
	for r in $RATES; do
		for l in $LOADS; do
			for ((i = 1; i <= REPS; i++)); do
				runs+=("$v $r $l $i")
			done
		done
	done
done
n_main=${#runs[@]}
n_ovh=0
for v in $VARIANTS; do n_ovh=$((n_ovh + REPS)); done
per_run=$((DURATION + 6))
est_main=$((n_main * per_run))
est_ovh=$((n_ovh * 100))
log "main runs: $n_main (about $((est_main / 60)) min), overhead runs: $n_ovh (about $((est_ovh / 60)) min)"
log "results go to $OUT"
[[ $list_only -eq 1 ]] && exit 0

#---- helpers ----
kill_leftovers() {
	pkill -f build/edr_noise 2>/dev/null
	pkill -f build/edr_attack 2>/dev/null
	pkill -x stress-ng 2>/dev/null
	pkill -f llama-bench 2>/dev/null
	pkill -f build/edr_consumer 2>/dev/null
	return 0
}

cleanup_files() { ./workloads/cleanup.sh >/dev/null 2>&1; }

on_exit() {
	kill_leftovers
	cleanup_files
	[[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null
}
trap 'log "stopped"; exit 130' INT TERM
trap on_exit EXIT

design_of() { echo "${1%samp}"; }
sampling_of() { [[ "$1" == *samp ]] && echo true || echo false; }

#waits until the consumer says it is attached (it prints a line to its log)
wait_ready() {
	local logf=$1 pid=$2
	for ((k = 0; k < 150; k++)); do
		grep -q "edr_consumer: design=" "$logf" 2>/dev/null && return 0
		kill -0 "$pid" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}

#---- one main run ----
run_one() {
	local variant=$1 rate=$2 load=$3 rep=$4
	local design sampling dir flag=""
	design=$(design_of "$variant")
	sampling=$(sampling_of "$variant")
	dir="$OUT/${variant}_rate${rate}_cpu${load}_rep${rep}"
	[[ -f "$dir/.complete" ]] && return 0

	rm -rf "$dir"
	mkdir -p "$dir"
	cleanup_files
	[[ "$sampling" == true ]] && flag="--sampling"

	cat > "$dir/config.json" <<CFG
{ "kind": "main", "variant": "$variant", "design": "$design", "mem": "$MEM", "rate": $rate,
  "cpu_load": "$load", "rep": $rep, "sampling": $sampling, "duration_s": $DURATION,
  "warmup_s": $WARMUP, "attack_window_s": $ATTACK_WINDOW, "attack_count": $COUNT }
CFG

	timeout $((DURATION + 40)) ./build/edr_consumer --design "$design" --mem "$MEM" \
		--duration "$DURATION" $flag --out "$dir" 2> "$dir/consumer.log" &
	local cpid=$!
	if ! wait_ready "$dir/consumer.log" "$cpid"; then
		echo "$(basename "$dir"): consumer did not start" >> "$FAILED"
		kill_leftovers
		return 1
	fi

	local lp np
	./workloads/cpu_load.sh --level "$load" --duration $((DURATION - 2)) >/dev/null 2>&1 &
	lp=$!
	./workloads/noise.sh --rate "$rate" --duration $((DURATION - 2)) >/dev/null 2> "$dir/noise.log" &
	np=$!

	sleep "$WARMUP"
	./workloads/run_attacks.sh --duration "$ATTACK_WINDOW" --count "$COUNT" --out "$dir" \
		>/dev/null 2> "$dir/attacks.log"

	wait "$cpid"
	wait "$lp" 2>/dev/null
	wait "$np" 2>/dev/null
	kill_leftovers

	if [[ ! -s "$dir/summary.json" || ! -s "$dir/injections.csv" ]]; then
		echo "$(basename "$dir"): missing summary.json or injections.csv" >> "$FAILED"
		return 1
	fi
	cleanup_files
	touch "$dir/.complete"
	return 0
}

#---- one overhead run: same benign job with and without the consumer ----
overhead_one() {
	local variant=$1 rep=$2
	local design sampling dir flag="" base mon
	design=$(design_of "$variant")
	sampling=$(sampling_of "$variant")
	dir="$OUT/overhead_${variant}_rep${rep}"
	[[ -f "$dir/.complete" ]] && return 0

	rm -rf "$dir"
	mkdir -p "$dir"
	cleanup_files
	[[ "$sampling" == true ]] && flag="--sampling"

	cat > "$dir/config.json" <<CFG
{ "kind": "overhead", "variant": "$variant", "design": "$design", "mem": "$MEM", "rate": 0,
  "cpu_load": "0", "rep": $rep, "sampling": $sampling, "benign": "compile" }
CFG

	base=$(./workloads/benign.sh compile 2>/dev/null)

	timeout 300 ./build/edr_consumer --design "$design" --mem "$MEM" $flag \
		--out "$dir" 2> "$dir/consumer.log" &
	local cpid=$!
	if ! wait_ready "$dir/consumer.log" "$cpid"; then
		echo "$(basename "$dir"): consumer did not start" >> "$FAILED"
		kill_leftovers
		return 1
	fi
	mon=$(./workloads/benign.sh compile 2>/dev/null)
	kill -TERM "$cpid" 2>/dev/null
	wait "$cpid" 2>/dev/null
	kill_leftovers

	if [[ -z "$base" || -z "$mon" ]]; then
		echo "$(basename "$dir"): benign.sh gave no time" >> "$FAILED"
		return 1
	fi
	awk -v b="$base" -v m="$mon" 'BEGIN {
		printf "{ \"benign\": \"compile\", \"baseline_s\": %.3f, \"monitored_s\": %.3f, \"overhead_pct\": %.2f }\n",
			b, m, (m - b) / b * 100 }' > "$dir/overhead.json"
	cleanup_files
	touch "$dir/.complete"
	return 0
}

#---- go ----
if [[ $mode != overhead ]]; then
	#random order so no design always gets the first (cold) or last (tired) runs
	mapfile -t order < <(printf '%s\n' "${runs[@]}" | shuf)
	total=${#order[@]}
	idx=0
	for line in "${order[@]}"; do
		idx=$((idx + 1))
		read -r v r l i <<< "$line"
		if [[ -f "$OUT/${v}_rate${r}_cpu${l}_rep${i}/.complete" ]]; then
			continue
		fi
		log "[$idx/$total] $v rate=$r cpu=$l rep=$i"
		run_one "$v" "$r" "$l" "$i" || log "  failed, see $FAILED"
	done
fi

if [[ $mode != main ]]; then
	log "overhead runs"
	./workloads/benign.sh compile >/dev/null 2>&1     #warm up, builds the inputs once
	for v in $VARIANTS; do
		for ((i = 1; i <= REPS; i++)); do
			log "overhead $v rep=$i"
			overhead_one "$v" "$i" || log "  failed, see $FAILED"
		done
	done
fi

log "all done"
[[ -s "$FAILED" ]] && log "some runs failed, see $FAILED (run the script again to retry them)"
exit 0
