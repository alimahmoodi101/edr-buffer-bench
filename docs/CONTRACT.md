# Shared contract

This file fixes the formats every part depends on. If all four parts follow
it, they plug together without anyone needing to read anyone else's code.
**Need to change something here? Tell the group first.**

---

## 1. The event (kernel → user space)

Defined in [`include/event.h`](../include/event.h). Every event is 128 bytes:

| Field | Meaning |
|---|---|
| `seq` | Global sequence number given by the kernel, starting at 1. **A missing number = a lost event.** |
| `class_seq` | Sequence number inside the event's priority class (for counting critical loss). |
| `ts_ns` | Kernel timestamp, `bpf_ktime_get_ns()`. Same clock as `CLOCK_MONOTONIC` in user space. |
| `pid`, `tgid`, `ppid` | Thread id, process id, parent process id. **Use `tgid` as "the process".** |
| `uid` | Real uid of the caller. |
| `cpu` | CPU the event happened on. |
| `type` | See table below. |
| `prio` | `0` = low, `1` = high (critical). |
| `arg1`, `arg2` | Depends on type (table below). |
| `comm` | Process name (16 bytes). |
| `path` | File path (first 47 characters). |

| type | value | prio | path | arg1 | arg2 |
|---|---|---|---|---|---|
| `exec` | 1 | high | binary | – | – |
| `fork` | 2 | high | – | child pid | – |
| `open` | 3 | low | file | open flags | – |
| `write` | 4 | low | – | fd | bytes |
| `rename` | 5 | high | old name | – | – |
| `unlink` | 6 | high | file | – | – |
| `setuid` | 7 | high | – | new uid (effective) | – |
| `read` | 8 | low | – | fd | bytes |

Notes:
- `write` isn't listed in the proposal's class table. It's classed as **low** because it's very high volume. Ransomware detection should rely on `rename`/`unlink` (high) and use `write`/`open` only as supporting evidence.
- `fork` also fires for new threads, not only new processes.
- The consumer's own events are never traced (it would trace its own log writes forever).

## 2. The backend API (Part 1 → Parts 3, 4, 5)

User-space code **never touches eBPF**. It uses [`src/backend.h`](../src/backend.h) and links `build/libedr.a`:

```c
struct backend_opts o = BACKEND_OPTS_DEFAULT;
o.design = DESIGN_PRIO;        // DESIGN_FIFO / DESIGN_PERCPU / DESIGN_PRIO
o.mem_bytes = 4 << 20;         // same for every design
o.sampling = true;             // adaptive sampling, prio only
struct backend *b = backend_open(&o, on_event, my_state);  // on_event called per event
while (running) backend_poll(b, 100);
backend_stop(b);               // detach probes
while (backend_drain(b) > 0);  // read leftovers
backend_stats(b, &stats);      // emitted / drops / sampled_out / received
backend_mark_suspicious(b, tgid);  // detector flags a process -> never sampled
backend_close(b);
```

### How memory is split (keeps the comparison fair)
| Design | Kernel memory with `mem = 4 MiB` |
|---|---|
| FIFO | one 4 MiB ring buffer |
| Per-CPU | 1 MiB per CPU × 4 CPUs |
| Priority | high ring 1 MiB + low ring capped at 3 MiB (ring sizes must be powers of 2, so the low ring is allocated at 4 MiB and the kernel stops filling it at 3 MiB) |

### Adaptive sampling (implemented in the kernel; Part 4 owns tuning and evaluating it)
- Only in the priority design, only for low-priority events.
- When the low ring is ≥ 70% full, keep 1 in 2 low events; at ≥ 80%, 1 in 4; at ≥ 90%, 1 in 8.
- Never samples processes marked with `backend_mark_suspicious()`.
- Sampled-out events get **no sequence number**, so they're counted in `sampled_out`, not as loss.

## 3. Output files (every run writes into one folder)

The benchmark harness (Part 5) creates one folder per run:
```
results/<design>_rate<N>_cpu<L>_rep<R>/
    config.json       written by harness: design, mem, rate, cpu_load, rep, sampling
    summary.json      written by consumer (format below)
    alerts.csv        written by detector
    injections.csv    written by workload generator (ground truth)
    overhead.json     written by harness: benign workload time with / without monitoring
    events.csv        OPTIONAL, only for debugging (slows the consumer down)
```

### `events.csv` (consumer / evdump)
```
seq,class_seq,ts_ns,recv_ns,cpu,type,prio,pid,tgid,ppid,uid,arg1,arg2,comm,path
```
`recv_ns` = `CLOCK_MONOTONIC` when user space received it. `type` is the name (`exec`, `fork`, ...).

### `summary.json` (consumer / evdump)
```json
{ "design": "prio", "mem_bytes": 4194304, "duration_s": 30.0,
  "trace_read": true, "sampling": false,
  "emitted_total": 0, "emitted_high": 0, "emitted_low": 0,
  "received_high": 0, "received_low": 0,
  "lost_high": 0, "lost_low": 0,
  "kernel_drops_high": 0, "kernel_drops_low": 0,
  "sampled_out_high": 0, "sampled_out_low": 0,
  "perf_lost": 0, "out_of_order": 0 }
```
The consumer (Part 3) **adds** these keys:
`"ooo_pairs_critical"` (out-of-order pairs inside detected attack sequences), `"consumer_cpu_s"` (CPU seconds used by the consumer).

### `injections.csv` (workload generator, Part 2): the ground truth
```
attack,start_ns,end_ns,tgid
ransomware,123456789,123999999,4242
forkstorm,...
privesc,...
```
- `start_ns`/`end_ns` come from `clock_gettime(CLOCK_MONOTONIC)`. In bash, use `python3 -c 'import time;print(time.monotonic_ns())'`.
- `tgid` is the PID of the attacking process (the parent, for fork storm).
- `attack` is exactly one of `ransomware`, `forkstorm`, `privesc`.

### `alerts.csv` (detector, Part 4)
```
alert_ns,attack,tgid,first_event_ts_ns,first_event_seq
```
Detection latency = `alert_ns - first_event_ts_ns`. An injection counts as detected if an alert with the same `attack` and `tgid` exists, and its alert time falls between `start_ns` and `end_ns + 5 s`.

## 4. Command lines (so the harness can call everything)

```bash
sudo ./build/edr_consumer --design fifo|percpu|prio --mem 4M --duration 30 \
        [--sampling] [--no-read] --out results/<run>/          # Part 3/4

sudo ./workloads/run_attacks.sh --duration 30 --count 3 --out results/<run>/   # Part 2
./workloads/noise.sh --rate <events_per_sec> --duration 30                      # Part 2
./workloads/cpu_load.sh --level 0|50|100|150|llm --duration 30                 # Part 2
./workloads/benign.sh compile|copy|extract   # prints elapsed seconds          # Part 2

python3 analysis/analyze.py results/ --out analysis/figures/                    # Part 6
```

## 5. Attack definitions (Part 2 simulates them, Part 4 detects them)
| Attack | What the simulator does | Detector rule |
|---|---|---|
| ransomware | One process opens, reads, writes and renames ≥ 50 files in `/tmp/edr_sandbox/` within 5 s | ≥ 50 `rename` or `unlink` by one tgid within 5 s |
| forkstorm | One parent spawns ≥ 100 children within 1 s | ≥ 100 `fork` with the same tgid within 1 s |
| privesc | `setuid(0)`, then `exec` of `/bin/sh` | `setuid` with arg1 = 0, then `exec` of a shell by the same tgid within 2 s |
