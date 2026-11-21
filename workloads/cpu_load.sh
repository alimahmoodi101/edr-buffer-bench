#!/usr/bin/env bash
# cpu_load.sh - background CPU load for the given duration.
#
#   ./workloads/cpu_load.sh --level 0|50|100|150|llm --duration 30
#
#   0        no load (just sleeps, so the harness can treat every level alike)
#   50, 100  stress-ng, one worker per CPU at that % load
#   150      stress-ng, 1.5 workers per CPU at 100% (oversubscribed)
#   llm      llama.cpp inference on a small model, in a loop
#
# For llm: sudo apt install llama.cpp-tools, then put a small GGUF model
# (e.g. Qwen2.5-0.5B-Instruct Q4_K_M) in workloads/models/, or point
# LLM_MODEL at it. *.gguf files are git-ignored.
set -euo pipefail
source "$(dirname "$0")/common.sh"

level="" duration=30
while [[ $# -gt 0 ]]; do
	case "$1" in
	--level)    level="$2"; shift 2 ;;
	--duration) duration="$2"; shift 2 ;;
	*) die "usage: $0 --level 0|50|100|150|llm --duration SEC" ;;
	esac
done

ncpu=$(nproc)
case "$level" in
0)
	exec sleep "$duration" ;;
50|100)
	exec stress-ng --cpu "$ncpu" --cpu-load "$level" --timeout "${duration}s" --quiet ;;
150)
	exec stress-ng --cpu $(( ncpu * 3 / 2 )) --cpu-load 100 --timeout "${duration}s" --quiet ;;
llm)
	bench=$(command -v llama-bench || true)
	[[ -n "$bench" ]] || die "llama-bench not found: sudo apt install llama.cpp-tools"
	model="${LLM_MODEL:-$(ls "$REPO"/workloads/models/*.gguf 2>/dev/null | head -1 || true)}"
	[[ -f "$model" ]] || die "no model: put a .gguf in workloads/models/ or set LLM_MODEL"
	# llama-bench repeats the same generation; -r is large and timeout ends
	# it. Run it in the background so a SIGTERM/Ctrl-C to this script (e.g.
	# from the harness) is passed on instead of leaving llama-bench running.
	timeout "${duration}s" "$bench" -m "$model" -t "$ncpu" \
		-p 0 -n 128 -r 100000 >/dev/null 2>&1 &
	child=$!
	trap 'kill "$child" 2>/dev/null' TERM INT
	wait "$child" || true
	wait "$child" 2>/dev/null || true   # if a signal interrupted the first wait
	;;
*)
	die "unknown level '$level' (use 0, 50, 100, 150 or llm)" ;;
esac
