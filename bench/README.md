# Part 5: benchmark harness

`run_bench.sh` loops over design variant, event rate, CPU load and repeat, and writes one folder
per run into `results/` (formats: [docs/CONTRACT.md](../docs/CONTRACT.md) section 3).

```bash
sudo ./bench/run_bench.sh --list          # number of runs and estimated time
sudo ./bench/run_bench.sh --quick         # a few minutes, writes to /tmp/edr_quick_results
sudo env RATES="50000 200000 0" LOADS="0 150" REPS=3 ./bench/run_bench.sh   # the runs in the report
```

- Finished runs (with a `.complete` marker) are skipped, so it can be stopped and restarted.
- Run order is shuffled so no design always gets the first or last runs.
- Each main run: start consumer, start CPU load + noise, wait `WARMUP`, inject attacks, wait for the consumer.
- Each overhead run: time `benign.sh compile` without monitoring, then again with the consumer running
  (baseline is always measured first, so a small order effect is possible).
- Failed runs are listed in `results/failed.log`; run the script again to retry them.
- All settings (`VARIANTS`, `RATES`, `LOADS`, `REPS`, `MEM`, `DURATION`, ...) are environment variables, see the main README.
