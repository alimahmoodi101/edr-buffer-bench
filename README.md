# Preserving Security Events Under Burst Load

Operating Systems final project, section L4.
Ali Mahmoodi, Mahnum Ahmed, Sarosh Mehdi, Arqish Zaria

**Question:** when a Linux machine is under heavy load, which kernel-to-user event buffer design lets an EDR keep seeing attacks, and at what cost?

An EDR can only detect what reaches it, and events are most likely to be dropped exactly when an attack is running. We trace security events with eBPF, send them through one of three buffer designs, stress the machine, and measure event loss, ordering, detection rate, detection latency and overhead.

| Design | Mechanism |
|---|---|
| Shared FIFO | one BPF ring buffer for all CPUs |
| Per-CPU | BPF perf event array, one buffer per CPU |
| Priority-aware | separate high and low priority ring buffers, optional adaptive sampling of low-priority events |

## Results

<!-- RESULTS:START -->
Buffer memory 256K, mean ± std over the repeats. All graphs and tables: [`analysis/figures/`](analysis/figures/), numbers in [`analysis/figures/results_tables.md`](analysis/figures/results_tables.md).

**Event rate max, CPU load 0**

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 3 | 797812 ± 41026 | 32.87 ± 4.10 | 46.12 ± 6.39 | 0.00 ± 0.00 | 97.08 ± 0.63 | 29.6 ± 17.0 | 53.5 ± 5.7 | 53.6 ± 1.9 |
| Per-CPU | 3 | 208263 ± 23523 | 7.90 ± 4.36 | 0.48 ± 0.83 | 0.00 ± 0.00 | 38.31 ± 2.49 | 100.0 ± 0.0 | 30.6 ± 5.5 | 41.7 ± 0.9 |
| Priority | 3 | 734274 ± 16380 | 39.20 ± 1.51 | 0.00 ± 0.00 | 0.00 ± 0.00 | 96.90 ± 1.02 | 100.0 ± 0.0 | 67.1 ± 0.6 | 52.1 ± 1.4 |
| Prio+sampling | 3 | 755055 ± 80052 | 5.48 ± 1.15 | 0.00 ± 0.00 | 41.61 ± 7.08 | 97.94 ± 0.44 | 100.0 ± 0.0 | 63.1 ± 5.4 | 48.5 ± 3.1 |

**Highest paced event rate 200k, CPU load 0 (same offered load for every design)**

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 3 | 186715 ± 16 | 0.11 ± 0.13 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.12 ± 0.52 | 100.0 ± 0.0 | 11.1 ± 1.1 | 23.7 ± 0.8 |
| Per-CPU | 3 | 185390 ± 1579 | 4.35 ± 0.88 | 0.34 ± 0.30 | 0.00 ± 0.00 | 38.83 ± 0.83 | 100.0 ± 0.0 | 22.9 ± 3.7 | 35.9 ± 1.0 |
| Priority | 3 | 186729 ± 22 | 0.60 ± 0.57 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.21 ± 0.40 | 100.0 ± 0.0 | 10.9 ± 2.4 | 24.0 ± 1.1 |
| Prio+sampling | 3 | 186736 ± 6 | 0.01 ± 0.02 | 0.00 ± 0.00 | 0.65 ± 0.85 | 99.34 ± 0.14 | 100.0 ± 0.0 | 12.8 ± 3.7 | 23.2 ± 1.9 |
<!-- RESULTS:END -->

Experiments run: 4 design variants, event rates 50k, 200k and unpaced (as fast as possible), CPU load 0% and 150%, 3 repeats each (72 runs) plus 12 overhead runs, 256K buffer memory, 30 s per run, Ubuntu on WSL2 with 4 vCPUs. The 50% and 100% CPU levels, the local LLM load and a larger buffer budget were not run.

Graphs are in [`analysis/figures/`](analysis/figures/), tables in [`analysis/figures/results_tables.md`](analysis/figures/results_tables.md), and the check of our four hypotheses in [`analysis/figures/hypotheses.md`](analysis/figures/hypotheses.md).

## Pipeline

```
workloads -> eBPF probes -> buffer (3 designs) -> consumer + reorder -> detector -> result files -> analysis
```

1. **Workloads** create noise and CPU load and inject safe fake attacks. `injections.csv` records every injected attack (the ground truth).
2. **Probes** (`bpf/probes.bpf.c`) turn exec, fork, setuid, rename, unlink, open, write and read into 128-byte events. Each event gets a global sequence number and a kernel timestamp before it enters the buffer, so a dropped event always leaves a gap.
3. **Buffer**: the selected design carries events to user space. If it is full, the event is dropped and counted.
4. **Consumer** (`edr_consumer`) measures loss and ordering on the raw arrival order, then restores sequence order with a small reorder buffer (50 ms by default).
5. **Detector** matches three attack patterns and writes `alerts.csv`.
6. **Analysis** compares alerts with injections and computes all metrics and graphs.

## Setup

Ubuntu 24.04 VM, 4 vCPUs, 4 GB RAM or more.

```bash
git clone https://github.com/alimahmoodi101/edr-buffer-bench && cd edr-buffer-bench
sudo ./scripts/setup_vm.sh
sudo make test                          # 3-second run of every design
sudo ./bench/run_bench.sh --quick       # whole pipeline, a few minutes
```

For the `llm` CPU-load level, install llama.cpp and the model as described in [`workloads/README.md`](workloads/README.md).

On WSL2, limit it to 4 CPUs in `.wslconfig` (`processors=4`). On Ubuntu 26.04, install bpftool separately (`sudo apt install bpftool`) and run `make BPFTOOL=/usr/sbin/bpftool`.

## Running the experiments

`bench/run_bench.sh` loops over design variant, event rate, CPU load and repeats, and writes one folder per run in `results/`. Finished runs are skipped, so it can be stopped and restarted. `--list` prints the number of runs and the estimated time without running anything.

| Variable | Meaning | Default |
|---|---|---|
| `VARIANTS` | `fifo percpu prio priosamp` (`priosamp` = priority design with sampling) | all four |
| `RATES` | noise events per second, `0` = as fast as possible | `50000 200000 0` |
| `LOADS` | CPU load levels: `0 50 100 150 llm` | `0 100 150` |
| `REPS` | repeats per configuration | `5` |
| `MEM` | total kernel buffer memory, equal for every design | `256K` |
| `DURATION`, `WARMUP`, `ATTACK_WINDOW`, `COUNT` | run length, warm-up, attack window (seconds), injections per attack type | `30 3 20 3` |
| `OUT` | results folder | `results` |

Full matrix of the proposal, the LLM load level, and a larger memory budget for comparison:

```bash
sudo env RATES="10000 50000 100000 200000 0" LOADS="0 50 100 150" ./bench/run_bench.sh
sudo env RATES="50000 0" LOADS="llm" ./bench/run_bench.sh
sudo env MEM=4M RATES="0" LOADS="0 150" OUT=results_4m ./bench/run_bench.sh
```

## Analysis

```bash
python3 analysis/analyze.py results/ --out analysis/figures/
python3 analysis/analyze.py results/ results_4m/ --out analysis/figures/    # several memory budgets
python3 analysis/analyze.py results/ --out analysis/figures/ --update-readme
```

Needs `pandas`, `numpy` and `matplotlib`. Output is described in [`analysis/README.md`](analysis/README.md).

## Metrics

| Metric | Definition |
|---|---|
| Event loss | emitted sequence numbers minus distinct sequence numbers received, split into total loss and loss of high-priority (critical) events; cross-checked with the kernel drop counters |
| Events not seen | loss plus events removed on purpose by adaptive sampling (sampled events get no sequence number, so they are not counted as loss) |
| Ordering accuracy | `1 - out_of_order / received` on the raw arrival order, before the reorder buffer |
| Detection rate | injected attacks with a matching alert / injected attacks. A match needs the same attack and tgid and an alert time in `[start, end + 5 s]` |
| Detection latency | alert time minus the kernel timestamp of the first event of the matched sequence |
| Consumer CPU | CPU seconds of `edr_consumer` / run length |
| Application overhead | slowdown of a benign compile with monitoring on versus off |
| Achieved event rate | `(emitted + sampled out) / duration` (the configured rate is only a target) |

Every number in the graphs is the mean over the repeats of one configuration; error bars are the standard deviation.

## Notes and limitations

- All designs get the same total buffer memory: FIFO one ring of `MEM`, per-CPU `MEM / 4` per CPU, priority a high ring of `MEM / 4` and a low ring filled only up to `3 * MEM / 4`. Perf and ring buffer records have different headers, so equal memory is not exactly equal capacity.
- High priority: exec, fork, setuid, rename, unlink. Low priority: open, read, write.
- "Critical loss" covers all high-priority events on the machine, not only those of the injected attacks. Detection rate is the attack-level measure.
- The detector uses only high-priority events and sampling only affects low-priority ones, so sampling cannot reduce detection in this setup. It only changes loss and CPU cost.
- At the unpaced rate the designs do not reach the same event rate (the traced workload runs slower with some designs), so loss percentages there are not directly comparable. `analysis/figures/fig_achieved_rate.png` shows the rate each design really carried; the paced 200k rate is the like-for-like comparison.
- CPU load also slows the event generators, so 150% CPU load gives fewer events per second than 0% at the unpaced rate.
- The benign compile used for the overhead runs triggers one false ransomware alert per run (bulk deletion of build files), the same for every design.
- Detection latency includes up to one reorder window (50 ms) when an event before it was lost.
- Overhead is measured with a compile benchmark only, without background noise.
- Events carry the pid in the consumer's PID namespace, so tgids match `injections.csv` on WSL2 and in containers as well.
- All attack simulators work on dummy files in `/tmp/edr_sandbox/` and are meant to run in an isolated VM.

## Repository layout

```
include/event.h             shared event struct (kernel and user space)
docs/CONTRACT.md            file formats and command lines used by all parts
scripts/setup_vm.sh         installs packages and builds everything
Makefile                    builds libedr.a, evdump, edr_consumer, workload helpers
bpf/probes.bpf.c            eBPF probes and the three buffer designs
src/backend.{c,h}           user-space library: load a design, receive events, read counters
tools/evdump.c              test tool: run one design, print loss and ordering
consumer/consumer.c         edr_consumer: main loop, counters, output files
consumer/reorder.{c,h}      reorder buffer (min-heap on the sequence number)
consumer/detector.c         detector for the three attack patterns
workloads/                  noise, CPU load, attack simulators, benign workload
bench/run_bench.sh          experiment runner
analysis/analyze.py         metrics, tables and graphs
analysis/figures/           generated graphs and tables
results/                    raw experiment output (not committed)
```

Each run folder in `results/` holds `config.json`, `summary.json`, `alerts.csv`, `injections.csv` (and `overhead.json` for overhead runs). The exact formats are in [`docs/CONTRACT.md`](docs/CONTRACT.md).

## Components

| Part | What | Where | Owner |
|---|---|---|---|
| 0 | Setup, shared event format, contract | `include/`, `docs/`, `scripts/` | Ali Mahmoodi |
| 1 | eBPF probes and the three buffer designs | `bpf/`, `src/`, `tools/` | Ali Mahmoodi |
| 2 | Workload generator and attack simulators | `workloads/` | Sarosh Mehdi |
| 3 | Consumer, logger, reordering | `consumer/` | Sarosh Mehdi |
| 4 | Detector and adaptive sampling | `consumer/detector.c`, `bpf/probes.bpf.c` | Mahnum Ahmed |
| 5 | Benchmark harness | `bench/` | Mahnum Ahmed |
| 6 | Analysis and graphs | `analysis/` | Arqish Zaria |
| 7 | README and report | `README.md` | Arqish Zaria |

More detail: [`workloads/README.md`](workloads/README.md), [`consumer/README.md`](consumer/README.md).
