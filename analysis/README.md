# Analysis

```bash
python3 analysis/analyze.py results/ --out analysis/figures/
```

Reads every run folder in `results/` (format in [`docs/CONTRACT.md`](../docs/CONTRACT.md), section 3) and writes into `--out`:

| Output | Content |
|---|---|
| `runs.csv` | one row per run, all metrics |
| `summary_by_config.csv` | mean, std and number of repeats per memory budget, design, rate and CPU load |
| `detection_by_attack.csv` | detection per attack type and run |
| `overhead.csv` | benign compile time with and without monitoring |
| `results_tables.md` | summary tables |
| `hypotheses.md` | check of hypotheses H1 to H4 against the measured numbers |
| `fig_total_loss.png`, `fig_critical_loss.png` | event loss versus event rate, one panel per CPU load, one line per design |
| `fig_ordering.png`, `fig_ooo_critical.png` | ordering accuracy, out-of-order events inside detected attacks |
| `fig_detection_rate.png`, `fig_detection_by_attack.png` | detection rate overall and per attack |
| `fig_latency.png` | detection latency (log scale) |
| `fig_consumer_cpu.png`, `fig_overhead.png` | CPU cost of the pipeline, slowdown of the benign compile |
| `fig_sampling_effect.png` | priority design with and without adaptive sampling |
| `fig_heatmap.png` | critical loss, total loss and detection for every configuration |

Lines are the mean over the repeats, error bars the standard deviation. If the results contain more than one memory budget, every graph is written once per budget (`..._mem256K.png`).

Options: `--pdf` (also write PDFs), `--dpi`, `--include-incomplete` (also use runs without the `.complete` marker; unfinished runs are skipped by default), `--update-readme [FILE]` (refresh the results block in the README), and several results folders at once.

## Detection matching

An injection in `injections.csv` counts as detected if `alerts.csv` has an alert with the same `attack` and `tgid` and an alert time between `start_ns` and `end_ns + 5 s`. Alerts that match no injection are counted as false alerts.
