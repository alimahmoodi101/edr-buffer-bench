# Part 2: workloads and attack simulators

Everything follows [docs/CONTRACT.md](../docs/CONTRACT.md) sections 3–5. `make` builds the
two C helpers (`build/edr_attack`, `build/edr_noise`). Only `/tmp/edr_sandbox/` is touched
(override with `EDR_SANDBOX`).

| Script | What it does |
|---|---|
| `sudo ./run_attacks.sh --duration 30 --count 3 --out DIR` | Runs each attack `count` times (3×count injections), evenly spread over `duration`, and writes `DIR/injections.csv`. Run with sudo so `setuid(0)` really succeeds. |
| `./noise.sh --rate N --duration 30` | About N low-priority events/s (writes to `/dev/null` + opens of a sandbox file) from one worker per CPU. `--rate 0` = as fast as possible. Prints the rate it achieved. |
| `./cpu_load.sh --level 0\|50\|100\|150\|llm --duration 30` | `stress-ng`, one worker per CPU at L% (150 = 1.5 workers per CPU at 100%). `llm` runs `llama-bench` on a small GGUF model in a loop (see below). |
| `./benign.sh compile\|copy\|extract` | Prints elapsed seconds only. compile = `make -j` of a generated 200-file C project (~40-55 s on 4 WSL vCPUs); copy = `cp -r` of 500 MB; extract = `tar xf` of the same. Inputs are generated once and cached. |
| `./cleanup.sh [--all]` | Deletes attack/noise files (`--all`: also the ~1 GB of cached benign inputs). |
| `python3 check_attacks.py DIR` | Sanity check: are the injected attacks visible in `DIR/events.csv`? |

## Attacks (`edr_attack.c`)

Each attack runs in a freshly forked child. `tgid` in `injections.csv` is that child's PID, and
`start_ns`/`end_ns` come from `CLOCK_MONOTONIC` just before the fork and just after the child exits.

| Attack | Default | Detector threshold |
|---|---|---|
| ransomware | open, read, XOR, write, rename 64 files to `*.locked` (~3 ms) | 50 rename/unlink in 5 s |
| forkstorm | 128 children that exit immediately (~10 ms) | 100 forks in 1 s |
| privesc | `setuid(0)`, then `exec /bin/sh -c "exit 0"` | setuid(0) then shell exec within 2 s |

The defaults are a little above the thresholds, so an attack is only missed if events are actually lost.
Change them with `--files` / `--children`.

## Notes for the harness (Part 5)

- **Run `cleanup.sh` between runs, while no consumer is running.** Ransomware files are not
  deleted during a run, because deleting them is an unlink burst that looks exactly like ransomware.
- `/tmp` is a RAM-backed tmpfs on WSL. The benign inputs use ~1 GB of RAM while cached
  (`BENIGN_MB=100` makes them smaller). `copy` and `extract` take well under 1 s on tmpfs, so repeat them.
- On the 4-vCPU WSL2 box used for the report, unpaced noise reached roughly 730-800k events/s while traced (FIFO and priority designs; per-CPU carried only ~200k/s). With the small buffer used for all reported runs (`--mem 256K`) this overloads the buffers; larger budgets such as 4M were not part of the final runs.
- For `--level llm`, every machine needs llama.cpp and the model (`*.gguf` is git-ignored, ~490 MB):
  ```bash
  sudo apt install -y llama.cpp-tools
  mkdir -p workloads/models && wget -O workloads/models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
    https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf
  ```
  It runs `llama-bench` on the CPU only (`-t <ncpu>`, about 78 tokens/s on 4 WSL cores). `LLM_MODEL` overrides the model path.
- Measured CPU busy (4 vCPUs, 2 s warm-up): level 0 → 1.5%, 50 → 53%, 100 → 99.6%, 150 → 99.6%, llm → 99.6%.
  150 can't show as more than 100% busy; the extra load shows up as more processes waiting
  for a CPU, so the consumer gets scheduled less often.
