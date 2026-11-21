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
4. Optional, only for the `llm` CPU-load level: install llama.cpp and the model (see [`workloads/README.md`](workloads/README.md)).

**On WSL2 instead of a VM:** limit WSL to 4 CPUs by putting `[wsl2]` / `processors=4` in
`C:\Users\<you>\.wslconfig`, then run `wsl --shutdown`. On **Ubuntu 26.04**, bpftool is its own package
and the Makefile can't find it, so the build in `setup_vm.sh` fails at `gen skeleton`. Fix it with
`sudo apt install bpftool`, then `make BPFTOOL=/usr/sbin/bpftool`.

## Status

| Part | Owner | Folder | Status |
|---|---|---|---|
| 0. Setup, shared contract | Ali | `include/`, `docs/`, `scripts/` | ✅ done |
| 1. eBPF probes + 3 buffer designs | Ali | `bpf/`, `src/`, `tools/` | ✅ done, tested (+ PID namespace fix, see below) |
| 2. Workloads + attack simulators | Sarosh | `workloads/` | ✅ done, tested |
| 3. Consumer, logger, reordering | Sarosh | `consumer/` | ✅ done, tested; detector plugs in via `consumer/consumer.h` |
| 4. Detector + adaptive sampling eval | _?_ (same person as 3, or split) | `consumer/` | ⬜ |
| 5. Benchmark harness | _?_ | `bench/` | ⬜ |
| 6. Analysis + graphs | _?_ (same person as 5) | `analysis/` | ⬜ |

**Read [`docs/CONTRACT.md`](docs/CONTRACT.md) before you start.** It defines every file format and command line, so nobody has to wait for anybody else.

## Timeline (submission: Thursday 26 Nov)

| Day | Goal |
|---|---|
| Sat 21 | Parts 0 + 1 pushed ✅ · Parts 2 + 3 pushed ✅ (early) |
| Sun 22 | Parts 4, 5, 6 start in parallel. Everyone gets the VM working |
| Mon 23 | Detector working. Harness runs with `edr_consumer` + workloads |
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

### Change to Part 1: PID namespace fix (Ali, please review)

WSL2 and containers run Linux in their own **PID namespace**, so the kernel's global PIDs differ from
what `getpid()` and `ps` show. Before this fix, event tgids never matched `injections.csv` (0 of 6 attacks
matched) and the consumer traced its own writes, because `self_tgid` never matched.
`src/backend.c` now passes the namespace of `/proc/self/ns/pid` to the probes, and `fill_common()` in
`bpf/probes.bpf.c` uses `bpf_get_ns_current_pid_tgid()` for `pid`/`tgid` (and reads `ppid` at the same depth).
On a plain VM the values are unchanged, and `make test` passes for all three designs.
Known gap: the child pid in `fork` events (`arg1`) is still the global pid; no detector rule uses it.

## Parts 2 + 3: what's done

Details and every command: [`workloads/README.md`](workloads/README.md) and [`consumer/README.md`](consumer/README.md).

**Part 2, `workloads/`** (follows CONTRACT §3–5, only touches `/tmp/edr_sandbox/`)
- `run_attacks.sh` + `edr_attack.c`: ransomware (64 files), forkstorm (128 children), privesc (`setuid(0)` + `exec /bin/sh`), each in its own process; writes `injections.csv`
- `noise.sh` + `edr_noise.c`: paced low-priority events, one worker per CPU (asked for 50k/s, got 49,997/s)
- `cpu_load.sh`: stress-ng at 0/50/100/150%; `llm` = llama-bench with Qwen2.5-0.5B on the CPU
- `benign.sh`: timed compile (~12 s) / copy / extract of 500 MB, for the overhead runs
- `cleanup.sh` (between runs), `check_attacks.py` (are the injected attacks visible in `events.csv`?)

**Part 3, `consumer/`**
- `build/edr_consumer`: the CONTRACT §4 command line; writes `summary.json` (with `ooo_pairs_critical` and `consumer_cpu_s`), `alerts.csv`, and `events.csv` with `--events`
- reorder buffer (`--reorder-ms`, default 50): releases events in `seq` order as soon as nothing is missing, or after the window if an earlier event was lost
- detector hook for Part 4 in `consumer/consumer.h` (see Part 4 notes below)

**Tested on WSL2 (4 vCPUs, 4 MiB buffer):**

| Test | Result |
|---|---|
| prio, 50k ev/s noise + 6 attacks | 0 lost, 6/6 attacks visible, consumer not tracing itself |
| percpu, 150% CPU + unpaced noise (245k ev/s) | 0 lost; 43% arrived out of order, 0 late after the reorder buffer |
| CPU busy at levels 0 / 50 / 100 / 150 / llm | 1.5% / 53% / 99.6% / 99.6% / 99.6% |

**Open questions for the group**
- `run_attacks.sh --count 3` runs **each** attack 3 times (9 injections per run). Is that what we want, or 3 in total?
- `ooo_pairs_critical` counts out-of-order **events** (not every pair) among the high-priority events of processes that got an alert.
- 4 MiB of buffer showed no loss even at ~245k ev/s on this machine; the harness probably needs a smaller `--mem` (e.g. 256K) to separate the designs.

## Part notes for owners

### Part 4: detector (`consumer/`)
Create `consumer/detector.c` with `detector_init/event/tick/finish` (declared in `consumer/consumer.h`).
The consumer has empty default versions, and yours replace them at link time. Events arrive already in
`seq` order. Call `consumer_alert(attack, tgid, first_ts_ns, first_seq)` to write `alerts.csv`, and
`consumer_mark_suspicious(tgid)` so sampling never hides that process. Rules: CONTRACT §5.
Check your results against `injections.csv`; `workloads/check_attacks.py` shows what the events contain.

### Part 5: harness (`bench/`)
One script that loops over design × rate × CPU load × 5 repeats. For each run it:
1. starts the consumer
2. starts the CPU load and noise
3. waits for the warm-up
4. starts the attacks
5. waits for the measurement window and drain period
6. writes `config.json`

Then add the sampling on/off runs and the overhead runs (benign workload with and without monitoring).
`edr_consumer` and all the workload scripts exist now (commands in CONTRACT §4). Run
`./workloads/cleanup.sh` **between** runs, while no consumer is running: deleting the ransomware files
is itself an unlink burst the detector would flag.

### Part 6: analysis (`analysis/`)
Python + pandas. Read every `results/*/` folder and plot loss, critical loss, ordering, detection rate and latency against event rate and CPU load, one line per design, with mean ± std over the 5 repeats. You can start right now using `evdump --summary` output.
