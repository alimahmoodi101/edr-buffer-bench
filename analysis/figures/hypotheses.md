# Automatic check of H1-H4

Each table compares the designs in one configuration, using the mean over all repeats. Two numbers count as equal if they differ by less than the run-to-run spread (standard deviation), a small absolute tolerance or 5%; such cases are marked inconclusive and never as supported. At an unpaced rate the designs do not carry the same number of events per second, so loss comparisons there carry a caution; the paced rate is the like-for-like comparison. The verdicts are a starting point: read the numbers and the graphs before writing a conclusion.

## Memory 256K: Highest paced event rate max, CPU load 0 (same offered load for every design)

|  | Check | Measured | Verdict |
|---|---|---|---|
|  | (context) achieved events/s | FIFO 797812, Per-CPU 208263, Priority 734274, Prio+sampling 755055 | info |
| H1 | FIFO keeps events in order better than per-CPU (ordering accuracy %) | FIFO 97.08, Per-CPU 38.31, Priority 96.90 | supported |
| H1 | FIFO has the best ordering accuracy of the three designs | FIFO 97.08, Per-CPU 38.31, Priority 96.90 | inconclusive (equal to another design within the spread) |
| H1 | FIFO has the highest total loss (%) | FIFO 32.87, Per-CPU 7.90, Priority 39.20 | not supported (caution: the designs carried unequal event rates) |
| H1 | FIFO has the highest loss of critical (high-priority) events (%) | FIFO 46.12, Per-CPU 0.48, Priority 0.00 | supported (caution: the designs carried unequal event rates) |
| H1 | FIFO has the highest consumer CPU (% of one core) | FIFO 53.56, Per-CPU 41.68, Priority 52.13 | inconclusive (equal to another design within the spread) |
| H2 | Per-CPU has the lowest total loss (%) | FIFO 32.87, Per-CPU 7.90, Priority 39.20 | supported (caution: the designs carried unequal event rates) |
| H2 | Per-CPU has the lowest ordering accuracy (%) | FIFO 97.08, Per-CPU 38.31, Priority 96.90 | supported |
| H2 | Per-CPU has the most out-of-order events inside detected attack sequences | FIFO 0.00, Per-CPU 0.00, Priority 0.00 | not testable (no design had out-of-order events inside detected attacks) |
| H3 | Priority keeps critical loss near 0 (< 1%) while its total loss is high (>= 10%) | critical loss 0.00%, total loss 39.20% | supported |
| H3 | Priority loses fewer critical events than FIFO (%) | Priority 0.00, FIFO 46.12 | supported |
| H3 | Priority loses fewer critical events than per-CPU (%) | Priority 0.00, Per-CPU 0.48 | inconclusive (equal within the spread) |
| H3 | Cost: latency for low-priority events | not measured (only detection latency is) | not measured |
| H4 | Sampling does not reduce the detection rate | Priority 100.00, Prio+sampling 100.00 | supported |
| H4 | Sampling reduces events lost in the buffer (%) | Priority 39.20, Prio+sampling 5.48 | supported |
| H4 | (context) events not seen, including those sampled out on purpose (%) | Priority 39.20, Prio+sampling 44.75 | info |
| H4 | Sampling reduces consumer CPU (% of one core) | Priority 52.13, Prio+sampling 48.45 | supported |

## Memory 256K: Highest paced event rate max, CPU load 150 (same offered load for every design)

|  | Check | Measured | Verdict |
|---|---|---|---|
|  | (context) achieved events/s | FIFO 391935, Per-CPU 100803, Priority 404673, Prio+sampling 390408 | info |
| H1 | FIFO keeps events in order better than per-CPU (ordering accuracy %) | FIFO 99.18, Per-CPU 58.60, Priority 99.28 | supported |
| H1 | FIFO has the best ordering accuracy of the three designs | FIFO 99.18, Per-CPU 58.60, Priority 99.28 | inconclusive (equal to another design within the spread) |
| H1 | FIFO has the highest total loss (%) | FIFO 30.32, Per-CPU 6.85, Priority 38.96 | not supported (caution: the designs carried unequal event rates) |
| H1 | FIFO has the highest loss of critical (high-priority) events (%) | FIFO 11.87, Per-CPU 0.00, Priority 0.00 | supported (caution: the designs carried unequal event rates) |
| H1 | FIFO has the highest consumer CPU (% of one core) | FIFO 28.55, Per-CPU 25.71, Priority 28.40 | inconclusive (equal to another design within the spread) |
| H2 | Per-CPU has the lowest total loss (%) | FIFO 30.32, Per-CPU 6.85, Priority 38.96 | supported (caution: the designs carried unequal event rates) |
| H2 | Per-CPU has the lowest ordering accuracy (%) | FIFO 99.18, Per-CPU 58.60, Priority 99.28 | supported |
| H2 | Per-CPU has the most out-of-order events inside detected attack sequences | FIFO 0.00, Per-CPU 0.00, Priority 0.00 | not testable (no design had out-of-order events inside detected attacks) |
| H3 | Priority keeps critical loss near 0 (< 1%) while its total loss is high (>= 10%) | critical loss 0.00%, total loss 38.96% | supported |
| H3 | Priority loses fewer critical events than FIFO (%) | Priority 0.00, FIFO 11.87 | supported |
| H3 | Priority loses fewer critical events than per-CPU (%) | Priority 0.00, Per-CPU 0.00 | inconclusive (equal within the spread) |
| H3 | Cost: latency for low-priority events | not measured (only detection latency is) | not measured |
| H4 | Sampling does not reduce the detection rate | Priority 100.00, Prio+sampling 100.00 | supported |
| H4 | Sampling reduces events lost in the buffer (%) | Priority 38.96, Prio+sampling 3.15 | supported |
| H4 | (context) events not seen, including those sampled out on purpose (%) | Priority 38.96, Prio+sampling 44.38 | info |
| H4 | Sampling reduces consumer CPU (% of one core) | Priority 28.40, Prio+sampling 27.57 | inconclusive (equal within the spread) |

## Memory 256K: Highest paced event rate 200k, CPU load 0 (same offered load for every design)

|  | Check | Measured | Verdict |
|---|---|---|---|
|  | (context) achieved events/s | FIFO 186715, Per-CPU 185390, Priority 186729, Prio+sampling 186736 | info |
| H1 | FIFO keeps events in order better than per-CPU (ordering accuracy %) | FIFO 99.12, Per-CPU 38.83, Priority 99.21 | supported |
| H1 | FIFO has the best ordering accuracy of the three designs | FIFO 99.12, Per-CPU 38.83, Priority 99.21 | inconclusive (equal to another design within the spread) |
| H1 | FIFO has the highest total loss (%) | FIFO 0.11, Per-CPU 4.35, Priority 0.60 | not supported |
| H1 | FIFO has the highest loss of critical (high-priority) events (%) | FIFO 0.00, Per-CPU 0.34, Priority 0.00 | not supported |
| H1 | FIFO has the highest consumer CPU (% of one core) | FIFO 23.72, Per-CPU 35.91, Priority 24.04 | not supported |
| H2 | Per-CPU has the lowest total loss (%) | FIFO 0.11, Per-CPU 4.35, Priority 0.60 | not supported |
| H2 | Per-CPU has the lowest ordering accuracy (%) | FIFO 99.12, Per-CPU 38.83, Priority 99.21 | supported |
| H2 | Per-CPU has the most out-of-order events inside detected attack sequences | FIFO 0.00, Per-CPU 0.33, Priority 0.00 | inconclusive (equal to another design within the spread) |
| H3 | Priority keeps critical loss near 0 (< 1%) while its total loss is high (>= 10%) | critical loss 0.00%, total loss 0.60% | not testable (priority design lost only 0.6% in total) |
| H3 | Priority loses fewer critical events than FIFO (%) | Priority 0.00, FIFO 0.00 | inconclusive (equal within the spread) |
| H3 | Priority loses fewer critical events than per-CPU (%) | Priority 0.00, Per-CPU 0.34 | supported |
| H3 | Cost: latency for low-priority events | not measured (only detection latency is) | not measured |
| H4 | Sampling does not reduce the detection rate | Priority 100.00, Prio+sampling 100.00 | supported |
| H4 | Sampling reduces events lost in the buffer (%) | Priority 0.60, Prio+sampling 0.01 | supported |
| H4 | (context) events not seen, including those sampled out on purpose (%) | Priority 0.60, Prio+sampling 0.67 | info |
| H4 | Sampling reduces consumer CPU (% of one core) | Priority 24.04, Prio+sampling 23.19 | inconclusive (equal within the spread) |

## Memory 256K: application overhead (benign compile)

|  | Check | Measured | Verdict |
|---|---|---|---|
| H1 | FIFO has the highest application slowdown (%) | FIFO 9.02 ± 3.10, Per-CPU 5.28 ± 10.27, Priority 4.11 ± 6.52, Prio+sampling -0.48 ± 4.11 | inconclusive (equal to another design within the spread) |
