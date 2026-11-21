# Part 3: consumer, logger, reordering (+ the Part 4 detector hook)

`make` builds every `.c` file here into `build/edr_consumer`.

```bash
sudo ./build/edr_consumer --design fifo|percpu|prio --mem 4M --duration 30 \
     [--sampling] [--no-read] [--reorder-ms 50] [--events] --out results/<run>/
```

Writes `summary.json` and `alerts.csv` (plus `events.csv` with `--events`, which is slow) into `--out`,
owned by your normal user even when run with sudo.

| File | Role |
|---|---|
| `consumer.c` | Main loop. Measures loss/ordering on the raw arrival order (same numbers as `evdump`), writes the files, calls the detector. |
| `reorder.c/.h` | Reorder buffer: a min-heap on `seq`. An event is released as soon as it is the next expected `seq`, or after `--reorder-ms` if something before it is missing (lost). Events that arrive after a larger `seq` was released are delivered anyway and counted as `reorder_late`. |
| `consumer.h` | **The interface for Part 4.** |

## Part 4: adding the detector

Create `consumer/detector.c` and define these four functions. The consumer has empty default versions
(weak symbols), and yours replace them automatically, so no other file changes:

```c
#include "consumer.h"
void detector_init(void);
void detector_event(const struct edr_event *e);   // every event, in seq order
void detector_tick(__u64 now_ns);                  // ~every 10 ms: expire old window state
void detector_finish(void);
```

From the detector, call:
- `consumer_alert("ransomware"|"forkstorm"|"privesc", tgid, first_event_ts_ns, first_event_seq)` to write an `alerts.csv` line (`alert_ns` = now)
- `consumer_mark_suspicious(tgid)` so adaptive sampling never hides that process

## summary.json

Contains every key from CONTRACT §3, plus:
- `ooo_pairs_critical`: for each process that got an alert, how many of its high-priority events arrived after one of its own events with a larger `seq` (raw order, before reordering), summed
- `consumer_cpu_s`: CPU seconds (user + system) the consumer used while running
- extra, informational: `reorder_ms`, `reorder_late`, `reorder_timeouts` (gaps given up on), `reorder_peak_held`, `alerts`
