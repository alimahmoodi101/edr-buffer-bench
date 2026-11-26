## Buffer memory budget: 256K

72 runs, 24 configurations, 3-3 repeats each. Values are mean ± std over the runs.

### Event rate max, CPU load 0

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 3 | 797812 ± 41026 | 32.87 ± 4.10 | 46.12 ± 6.39 | 0.00 ± 0.00 | 97.08 ± 0.63 | 29.6 ± 17.0 | 53.5 ± 5.7 | 53.6 ± 1.9 |
| Per-CPU | 3 | 208263 ± 23523 | 7.90 ± 4.36 | 0.48 ± 0.83 | 0.00 ± 0.00 | 38.31 ± 2.49 | 100.0 ± 0.0 | 30.6 ± 5.5 | 41.7 ± 0.9 |
| Priority | 3 | 734274 ± 16380 | 39.20 ± 1.51 | 0.00 ± 0.00 | 0.00 ± 0.00 | 96.90 ± 1.02 | 100.0 ± 0.0 | 67.1 ± 0.6 | 52.1 ± 1.4 |
| Prio+sampling | 3 | 755055 ± 80052 | 5.48 ± 1.15 | 0.00 ± 0.00 | 41.61 ± 7.08 | 97.94 ± 0.44 | 100.0 ± 0.0 | 63.1 ± 5.4 | 48.5 ± 3.1 |

### Event rate max, CPU load 150

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 3 | 391935 ± 21974 | 30.32 ± 0.66 | 11.87 ± 0.85 | 0.00 ± 0.00 | 99.18 ± 0.11 | 96.3 ± 6.4 | 75.8 ± 9.3 | 28.6 ± 0.5 |
| Per-CPU | 3 | 100803 ± 1300 | 6.85 ± 2.23 | 0.00 ± 0.00 | 0.00 ± 0.00 | 58.60 ± 0.85 | 100.0 ± 0.0 | 42.2 ± 4.5 | 25.7 ± 0.2 |
| Priority | 3 | 404673 ± 15217 | 38.96 ± 0.71 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.28 ± 0.04 | 100.0 ± 0.0 | 69.2 ± 5.6 | 28.4 ± 0.4 |
| Prio+sampling | 3 | 390408 ± 7182 | 3.15 ± 0.15 | 0.00 ± 0.00 | 42.58 ± 0.39 | 99.48 ± 0.04 | 100.0 ± 0.0 | 60.4 ± 1.8 | 27.6 ± 0.3 |

### Highest paced event rate 200k, CPU load 0 (same offered load for every design)

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 3 | 186715 ± 16 | 0.11 ± 0.13 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.12 ± 0.52 | 100.0 ± 0.0 | 11.1 ± 1.1 | 23.7 ± 0.8 |
| Per-CPU | 3 | 185390 ± 1579 | 4.35 ± 0.88 | 0.34 ± 0.30 | 0.00 ± 0.00 | 38.83 ± 0.83 | 100.0 ± 0.0 | 22.9 ± 3.7 | 35.9 ± 1.0 |
| Priority | 3 | 186729 ± 22 | 0.60 ± 0.57 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.21 ± 0.40 | 100.0 ± 0.0 | 10.9 ± 2.4 | 24.0 ± 1.1 |
| Prio+sampling | 3 | 186736 ± 6 | 0.01 ± 0.02 | 0.00 ± 0.00 | 0.65 ± 0.85 | 99.34 ± 0.14 | 100.0 ± 0.0 | 12.8 ± 3.7 | 23.2 ± 1.9 |

### Mean over every configuration

| Design | runs | events/s | total loss % | critical loss % | sampled out % | ordering acc. % | detection % | latency ms | consumer CPU % |
|---|---|---|---|---|---|---|---|---|---|
| FIFO | 18 | 276123 ± 268396 | 10.90 ± 15.17 | 9.75 ± 17.45 | 0.00 ± 0.00 | 99.04 ± 1.00 | 87.7 ± 27.5 | 35.5 ± 23.9 | 28.0 ± 12.7 |
| Per-CPU | 18 | 115482 ± 64596 | 4.33 ± 3.65 | 0.42 ± 1.17 | 0.00 ± 0.00 | 55.80 ± 14.03 | 99.4 ± 2.6 | 28.6 ± 9.5 | 29.2 ± 7.4 |
| Priority | 18 | 267659 ± 247643 | 13.96 ± 18.38 | 0.00 ± 0.00 | 0.00 ± 0.00 | 99.02 ± 1.06 | 100.0 ± 0.0 | 41.0 ± 23.5 | 28.1 ± 12.0 |
| Prio+sampling | 18 | 268751 ± 254696 | 1.44 ± 2.24 | 0.00 ± 0.00 | 15.36 ± 19.78 | 99.24 ± 0.69 | 100.0 ± 0.0 | 34.4 ± 21.8 | 26.9 ± 11.1 |

### Target vs achieved event rate (median over runs)

| target rate | achieved events/s |
|---|---|
| 50k | 46,768 |
| 200k | 186,726 |
| max | 404,306 |

### Application overhead (benign compile with and without monitoring)

| Design | runs | baseline s | monitored s | slowdown % | consumer CPU % | false alerts |
|---|---|---|---|---|---|---|
| FIFO | 3 | 47.07 ± 2.27 | 51.32 ± 2.86 | 9.02 ± 3.10 | 2.2 ± 0.1 | 3 |
| Per-CPU | 3 | 43.67 ± 4.97 | 45.81 ± 4.70 | 5.28 ± 10.27 | 2.1 ± 0.1 | 3 |
| Priority | 3 | 42.54 ± 3.44 | 44.15 ± 1.33 | 4.11 ± 6.52 | 2.2 ± 0.2 | 3 |
| Prio+sampling | 3 | 44.41 ± 3.18 | 44.12 ± 1.90 | -0.48 ± 4.11 | 2.2 ± 0.0 | 3 |

### Detection rate per attack (%, pooled over all configurations)

| Design | ransomware | forkstorm | privesc |
|---|---|---|---|
| FIFO | 88.9 | 83.3 | 90.7 |
| Per-CPU | 98.1 | 100.0 | 100.0 |
| Priority | 100.0 | 100.0 | 100.0 |
| Prio+sampling | 100.0 | 100.0 | 100.0 |
