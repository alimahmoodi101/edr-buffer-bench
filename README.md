# Preserving Security Events Under Burst Load

OS Final Project, Section L4: Ali Mahmoodi, Mahnum Ahmed, Sarosh Mehdi, Arqish Zaria.

**Question:** when a Linux machine is under heavy load, which kernel-to-user event buffer design lets an EDR keep seeing attacks, and at what cost?

We trace security events with eBPF and push them through one of three buffer designs:

| Design | Mechanism |
|---|---|
| Shared FIFO | one BPF ring buffer for all CPUs |
| Per-CPU | BPF perf event array, one buffer per CPU |
| Priority-aware | separate high / low priority ring buffers, optional adaptive sampling |

We then stress each design and measure event loss, ordering, detection rate/latency and overhead.

---

## Quick start

1. **VM:** Ubuntu **24.04**, 4 vCPUs, 4+ GB RAM, 20 GB disk. Take a snapshot after setup.
2. Set up and build:
   ```bash
   git clone <repo-url> && cd edr-buffer-bench
   sudo ./scripts/setup_vm.sh
   ```
3. Check that it works:
   ```bash
   sudo ./build/evdump --design prio --duration 5 --no-read
   sudo ./build/evdump --design fifo --print          # live events, Ctrl-C to stop
   sudo make test                                     # 3-second run of every design
   ```

## Status

| Part | Owner | Folder | Status |
|---|---|---|---|
| 0. Setup, shared contract | Ali | `include/`, `docs/`, `scripts/` | ✅ done |
| 1. eBPF probes + 3 buffer designs | Ali | `bpf/`, `src/`, `tools/` | ✅ done, tested |
| 2. Workloads + attack simulators | Sarosh | `workloads/` | ✅ done, tested (see `workloads/README.md`) |
| 3. Consumer, logger, reordering | Sarosh | `consumer/` | ✅ done, tested; detector plugs in via `consumer/consumer.h` |
| 4. Detector + adaptive sampling eval | _?_ (same person as 3, or split) | `consumer/` | ⬜ |
| 5. Benchmark harness | _?_ | `bench/` | ⬜ |
| 6. Analysis + graphs | _?_ (same person as 5) | `analysis/` | ⬜ |

**Read [`docs/CONTRACT.md`](docs/CONTRACT.md) before you start.** It defines every file format and command line, so nobody has to wait for anybody else.

## Timeline (submission: Thursday 26 Nov)

| Day | Goal |
|---|---|
| Sat 21 | Parts 0 + 1 pushed ✅ |
| Sun 22 | Parts 2, 3, 5, 6 all start in parallel. Everyone gets the VM working |
| Mon 23 | Part 2 and Part 3 done. Detector working. Harness runs with `evdump` |
| Tue 24 | Integration (harness + consumer + workloads). **Full experiment run overnight** (~5 h) |
| Wed 25 | Graphs, report, slides, README polish |
| Thu 26 | Submit |

## Repository layout

```
include/event.h        shared event struct (kernel + user space)          [Part 0]
docs/CONTRACT.md       file formats and command lines everyone follows    [Part 0]
scripts/setup_vm.sh    installs everything and builds                     [Part 0]
bpf/probes.bpf.c       eBPF probes + all three buffer designs             [Part 1]
src/backend.{c,h}      user-space library: load a design, receive events  [Part 1]
tools/evdump.c         test tool: run a design, report loss / ordering    [Part 1]
workloads/             benign bursts, attack simulators, noise, CPU load  [Part 2]
consumer/              consumer, reordering, detector, sampling           [Part 3+4]
bench/                 automated experiment runner                        [Part 5]
analysis/              metrics and graphs from results/                   [Part 6]
results/               experiment output (not committed)
build/                 compiled output (not committed)
```

## Part 1: what's done

- **Probes** (`bpf/probes.bpf.c`): exec, fork, setuid/setreuid/setresuid, rename/renameat/renameat2, unlink/unlinkat (all **high** priority); openat, write, read (**low** priority).
- Every event gets a **global sequence number** and a **kernel timestamp** *before* it enters the buffer, so a full buffer always leaves a visible gap.
- Kernel counters per class: `emitted`, `drops`, `sampled_out`.
- All three designs use **the same memory budget** (see CONTRACT §2).
- **Adaptive sampling** is implemented in the kernel (priority design, `--sampling`).
- The probes never trace the consumer itself.

First test, on a 2-CPU sandbox with a deliberately tiny 64 KiB buffer under a burst of ~670k events/s:

| Design | Critical events lost | Total lost | Out of order |
|---|---|---|---|
| FIFO | 30% | 63% | 0.03% |
| Per-CPU | 0.8% | 85% | 34% |
| Priority | **0%** | 70% | 1.2% |
| Priority + sampling | **0%** | 28% | 1.7% |

## Part notes for owners

### Part 2: workloads (`workloads/`)
Shell or C scripts, see CONTRACT §4 and §5. Must write `injections.csv` with `CLOCK_MONOTONIC` timestamps. **Only ever touch files in `/tmp/edr_sandbox/`.**
- `noise.sh --rate N` should hit roughly N events/s. Check it with `evdump`: emitted ÷ duration.
- `cpu_load.sh` uses `stress-ng --cpu 4 --cpu-load <L>`. For 150%, use 6 workers at 100%. For `llm`, run llama.cpp with a small model (e.g. Qwen2.5-0.5B GGUF) in a loop.
- `benign.sh`: compile (e.g. build a small project like `make -j4` of `stress-ng` source), copy (`cp -r` a 500 MB folder), extract (`tar xf`).

### Part 3 + 4: consumer and detector (`consumer/`)
Put `.c` files in `consumer/` and `make` builds `build/edr_consumer` automatically, linked with the backend. Start by copying `tools/evdump.c`: it already has the option parsing, the poll loop, loss counting and `summary.json`. Then add:
- a reorder buffer (hold events for a short window, then release them sorted by `seq`)
- the three detector rules (CONTRACT §5), writing `alerts.csv`
- `backend_mark_suspicious(tgid)` when a process looks suspicious, so sampling never hides it

### Part 5: harness (`bench/`)
One script that loops over design × rate × CPU load × 5 repeats. For each run it:
1. starts the consumer
2. starts the CPU load and noise
3. waits for the warm-up
4. starts the attacks
5. waits for the measurement window and drain period
6. writes `config.json`

Then add the sampling on/off runs and the overhead runs (benign workload with and without monitoring). You can build and test it with `evdump` before the consumer exists.

### Part 6: analysis (`analysis/`)
Python + pandas. Read every `results/*/` folder and plot loss, critical loss, ordering, detection rate and latency against event rate and CPU load, one line per design, with mean ± std over the 5 repeats. You can start right now using `evdump --summary` output.
