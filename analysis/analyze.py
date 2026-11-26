#!/usr/bin/env python3
"""analyze.py - Part 6: turn results/<run>/ folders into tables and graphs.

    python3 analysis/analyze.py results/ --out analysis/figures/
    python3 analysis/analyze.py results/ --out analysis/figures/ --update-readme
    python3 analysis/analyze.py results/ results_4m/ --out analysis/figures/   (several memory budgets)

What it reads (docs/CONTRACT.md section 3), one folder per run:
    config.json      variant, design, mem, rate, cpu_load, rep, kind (main|overhead)
    summary.json     written by edr_consumer (emitted / lost / sampled / ordering / cpu)
    alerts.csv       written by the detector
    injections.csv   ground truth written by the attack generator
    overhead.json    benign compile time with / without monitoring (overhead runs)

What it writes into --out:
    runs.csv                 one row per run, every metric
    summary_by_config.csv    mean / std / n over the repeats of each configuration
    detection_by_attack.csv  detection rate per attack type
    overhead.csv             application slowdown per variant
    results_tables.md        markdown tables to paste into the report
    hypotheses.md            automatic check of H1-H4 against the numbers
    fig_*.png                the graphs (add --pdf for vector copies)

Variants: fifo, percpu, prio, priosamp (= prio + adaptive sampling).
Only pandas, numpy and matplotlib are needed.
"""
import argparse
import csv
import json
import math
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

SEC_NS = 1_000_000_000
DETECT_SLACK_NS = 5 * SEC_NS            # CONTRACT section 3: alert within end_ns + 5 s
VARIANTS = ["fifo", "percpu", "prio", "priosamp"]
LABELS = {
    "fifo": "Shared FIFO (ring buffer)",
    "percpu": "Per-CPU (perf buffer)",
    "prio": "Priority-aware",
    "priosamp": "Priority + adaptive sampling",
}
SHORT = {"fifo": "FIFO", "percpu": "Per-CPU", "prio": "Priority", "priosamp": "Prio+sampling"}
COLORS = {"fifo": "#1f77b4", "percpu": "#d62728", "prio": "#2ca02c", "priosamp": "#9467bd"}
MARKERS = {"fifo": "o", "percpu": "s", "prio": "^", "priosamp": "D"}
ATTACKS = ["ransomware", "forkstorm", "privesc"]
CORE = ["fifo", "percpu", "prio"]       # the three designs of the research question

# metric name -> (axis label, column in runs.csv)
METRICS = [
    "total_loss_pct", "critical_loss_pct", "sampled_pct", "unseen_pct",
    "ordering_acc_pct", "ooo_critical", "reorder_late",
    "detection_rate_pct", "latency_ms", "false_alerts",
    "consumer_cpu_pct", "achieved_rate",
]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def warn(msg):
    print(f"analyze: warning: {msg}", file=sys.stderr)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        warn(f"cannot read {path}: {e}")
        return None


def read_csv(path):
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except OSError:
        return []


def to_int(x, default=0):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return default


def human_bytes(n):
    n = int(n)
    for unit, size in (("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if n >= size and n % size == 0:
            return f"{n // size}{unit}"
    return str(n)


def fmt_rate(x):
    if x == 0:
        return "max"
    if x >= 1e6:
        return f"{x / 1e6:.1f}M"
    if x >= 1e3:
        return f"{x / 1e3:.0f}k"
    return f"{x:.0f}"


def load_key(x):
    """cpu_load sort key: numbers first (0, 50, 100, 150), then llm."""
    s = str(x)
    return (0, int(s)) if s.isdigit() else (1, s)


def rate_key(x):
    """rate sort key: ascending, with 0 (= unpaced, as fast as possible) last."""
    x = int(x)
    return (1, 0) if x == 0 else (0, x)


def load_label(x):
    s = str(x)
    return f"CPU load {s}%" if s.isdigit() else "CPU load: local LLM"


def mean(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return sum(xs) / len(xs) if xs else float("nan")


def pm(m, s, digits=2):
    if m is None or (isinstance(m, float) and math.isnan(m)):
        return "n/a"
    if s is None or (isinstance(s, float) and math.isnan(s)):
        s = 0.0
    return f"{m:.{digits}f} ± {s:.{digits}f}"


# --------------------------------------------------------------------------
# loading one run
# --------------------------------------------------------------------------
def match_detections(injections, alerts):
    """CONTRACT section 3: an injection is detected if an alert with the same
    attack and tgid exists whose alert time lies in [start_ns, end_ns + 5 s].
    Returns (per-injection results, number of alerts that matched nothing)."""
    used = set()
    results = []
    for inj in injections:
        best = None
        start, end = to_int(inj["start_ns"]), to_int(inj["end_ns"])
        for k, a in enumerate(alerts):
            if k in used or a["attack"] != inj["attack"] or to_int(a["tgid"]) != to_int(inj["tgid"]):
                continue
            t = to_int(a["alert_ns"])
            if start <= t <= end + DETECT_SLACK_NS:
                if best is None or t < to_int(alerts[best]["alert_ns"]):
                    best = k
        if best is None:
            results.append({"attack": inj["attack"], "detected": False, "latency_ms": float("nan")})
        else:
            used.add(best)
            a = alerts[best]
            first = to_int(a["first_event_ts_ns"])
            lat = (to_int(a["alert_ns"]) - first) / 1e6 if first else float("nan")
            if lat < 0:
                lat = float("nan")
            results.append({"attack": inj["attack"], "detected": True, "latency_ms": lat})
    return results, len(alerts) - len(used)


def variant_of(cfg, summ):
    if cfg.get("variant"):
        return str(cfg["variant"])
    design = cfg.get("design") or summ.get("design")
    samp = bool(cfg.get("sampling", summ.get("sampling", False)))
    return design + ("samp" if samp and design == "prio" else "")


def build_record(d, cfg, summ):
    emitted = to_int(summ.get("emitted_total"))
    e_high = to_int(summ.get("emitted_high"))
    s_out = to_int(summ.get("sampled_out_high")) + to_int(summ.get("sampled_out_low"))
    lost_h, lost_l = to_int(summ.get("lost_high")), to_int(summ.get("lost_low"))
    recv = to_int(summ.get("received_high")) + to_int(summ.get("received_low"))
    dur = float(summ.get("duration_s") or cfg.get("duration_s") or float("nan"))
    offered = emitted + s_out           # sampled-out events never got a seq number
    mem_b = to_int(summ.get("mem_bytes"))
    rec = {
        "run": d.name,
        "variant": variant_of(cfg, summ),
        "design": cfg.get("design") or summ.get("design"),
        "mem_bytes": mem_b,
        "mem": human_bytes(mem_b) if mem_b else str(cfg.get("mem")),
        "rate": to_int(cfg.get("rate")),
        "cpu_load": str(cfg.get("cpu_load")),
        "rep": to_int(cfg.get("rep")),
        "fake": bool(cfg.get("fake", False)),
        "duration_s": dur,
        "offered_events": offered,
        "emitted_events": emitted,
        "lost_events": lost_h + lost_l,
        "lost_critical": lost_h,
        "sampled_out": s_out,
        "achieved_rate": offered / dur if dur and dur > 0 else float("nan"),
        "total_loss_pct": 100.0 * (lost_h + lost_l) / emitted if emitted else float("nan"),
        "critical_loss_pct": 100.0 * lost_h / e_high if e_high else float("nan"),
        "sampled_pct": 100.0 * s_out / offered if offered else float("nan"),
        "unseen_pct": 100.0 * (lost_h + lost_l + s_out) / offered if offered else float("nan"),
        "ordering_acc_pct": 100.0 * (1 - to_int(summ.get("out_of_order")) / recv) if recv else float("nan"),
        "ooo_critical": to_int(summ.get("ooo_pairs_critical")),
        "reorder_late": to_int(summ.get("reorder_late")),
        "consumer_cpu_pct": 100.0 * float(summ.get("consumer_cpu_s", float("nan"))) / dur
        if dur and dur > 0 else float("nan"),
        "alerts": to_int(summ.get("alerts")),
    }
    return rec


def load_results(roots, include_incomplete):
    candidates = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            sys.exit(f"analyze: {root} is not a folder")
        found = [d for d in sorted(root.iterdir()) if d.is_dir() and (d / "config.json").exists()]
        if not found:
            warn(f"no run folders (with config.json) in {root}")
        candidates += found
    if not candidates:
        sys.exit("analyze: no run folders found")

    any_complete = any((d / ".complete").exists() for d in candidates)
    main_rows, ovh_rows, det_rows, skipped = [], [], [], []
    for d in candidates:
        if any_complete and not include_incomplete and not (d / ".complete").exists():
            skipped.append(d.name)
            continue
        cfg, summ = read_json(d / "config.json"), read_json(d / "summary.json")
        if cfg is None or summ is None:
            skipped.append(d.name)
            continue
        rec = build_record(d, cfg, summ)
        alerts = read_csv(d / "alerts.csv")
        kind = cfg.get("kind", "main")
        if kind == "overhead":
            ov = read_json(d / "overhead.json") or {}
            rec.update(baseline_s=ov.get("baseline_s", float("nan")),
                       monitored_s=ov.get("monitored_s", float("nan")),
                       overhead_pct=ov.get("overhead_pct", float("nan")),
                       false_alerts=len(alerts))
            ovh_rows.append(rec)
            continue
        inj = read_csv(d / "injections.csv")
        if not inj:
            skipped.append(d.name)
            continue
        res, fp = match_detections(inj, alerts)
        rec["injected"] = len(res)
        rec["detected"] = sum(r["detected"] for r in res)
        rec["detection_rate_pct"] = 100.0 * rec["detected"] / len(res)
        lats = [r["latency_ms"] for r in res if r["detected"] and not math.isnan(r["latency_ms"])]
        rec["latency_ms"] = mean(lats)
        rec["false_alerts"] = fp
        main_rows.append(rec)
        for atk in ATTACKS:
            sub = [r for r in res if r["attack"] == atk]
            if sub:
                det_rows.append({**{k: rec[k] for k in ("run", "variant", "mem", "mem_bytes", "rate", "cpu_load", "rep")},
                                 "attack": atk, "injected": len(sub),
                                 "detected": sum(r["detected"] for r in sub),
                                 "latency_ms": mean([r["latency_ms"] for r in sub if r["detected"]])})
    if skipped:
        warn(f"skipped {len(skipped)} incomplete or broken run folders (first: {skipped[0]}); "
             "use --include-incomplete to keep unfinished runs")
    if not main_rows:
        sys.exit("analyze: no usable main runs found")
    runs = pd.DataFrame(main_rows)
    ovh = pd.DataFrame(ovh_rows)
    det = pd.DataFrame(det_rows)
    return runs, ovh, det


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------
def aggregate(runs):
    keys = ["mem_bytes", "mem", "variant", "rate", "cpu_load"]
    g = runs.groupby(keys)
    agg = g[METRICS].agg(["mean", "std"])
    agg.columns = [f"{a}_{b}" for a, b in agg.columns]
    agg["n"] = g.size()
    agg = agg.reset_index()
    agg["_v"] = agg["variant"].map({v: i for i, v in enumerate(VARIANTS)}).fillna(99)
    agg["_r"] = agg["rate"].map(lambda r: rate_key(r))
    agg["_l"] = agg["cpu_load"].map(lambda l: load_key(l))
    agg = agg.sort_values(["mem_bytes", "_r", "_l", "_v"]).drop(columns=["_v", "_r", "_l"])
    return agg.reset_index(drop=True)


def variants_present(df):
    present = [v for v in VARIANTS if v in set(df["variant"])]
    return present + sorted(set(df["variant"]) - set(VARIANTS))


def rates_present(df):
    return sorted(set(df["rate"]), key=rate_key)


def loads_present(df):
    return sorted(set(df["cpu_load"]), key=load_key)


# --------------------------------------------------------------------------
# plotting
# --------------------------------------------------------------------------
class Plotter:
    def __init__(self, outdir, pdf, dpi, synthetic):
        self.outdir, self.pdf, self.dpi, self.synthetic = Path(outdir), pdf, dpi, synthetic
        self.written = []
        plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.3,
                             "axes.spines.top": False, "axes.spines.right": False})

    def save(self, fig, name):
        if self.synthetic:
            fig.text(0.5, 0.5, "SYNTHETIC DATA", fontsize=40, color="red", alpha=0.15,
                     ha="center", va="center", rotation=25)
        fig.tight_layout()
        path = self.outdir / f"{name}.png"
        fig.savefig(path, dpi=self.dpi)
        if self.pdf:
            fig.savefig(self.outdir / f"{name}.pdf")
        plt.close(fig)
        self.written.append(path.name)

    def lines(self, agg, runs, metric, ylabel, name, title, ylog=False, ylim=None):
        """One panel per CPU load, x = event rate, one line per variant, mean +/- std."""
        loads, rates = loads_present(agg), rates_present(agg)
        variants = variants_present(agg)
        ach = {r: runs.loc[runs["rate"] == r, "achieved_rate"].median() for r in rates}
        fig, axes = plt.subplots(1, len(loads), figsize=(3.6 * len(loads) + 0.8, 3.8),
                                 sharey=True, squeeze=False)
        for ax, load in zip(axes[0], loads):
            sub = agg[agg["cpu_load"] == load]
            for i, v in enumerate(variants):
                s = sub[sub["variant"] == v].set_index("rate")
                xs = [k + (i - (len(variants) - 1) / 2) * 0.06 for k, r in enumerate(rates) if r in s.index]
                ys = [s.loc[r, f"{metric}_mean"] for r in rates if r in s.index]
                es = [s.loc[r, f"{metric}_std"] for r in rates if r in s.index]
                es = [0 if (e is None or math.isnan(e)) else e for e in es]
                ax.errorbar(xs, ys, yerr=es, color=COLORS.get(v, "gray"), marker=MARKERS.get(v, "o"),
                            ms=5, lw=1.4, capsize=3, label=SHORT.get(v, v))
            ax.set_xticks(range(len(rates)))
            ax.set_xticklabels([f"{fmt_rate(r)}\n(≈{fmt_rate(ach[r])}/s)" if r else f"max\n(≈{fmt_rate(ach[r])}/s)"
                                for r in rates], fontsize=7.5)
            ax.set_xlim(-0.4, len(rates) - 0.6)
            ax.set_title(load_label(load), fontsize=9)
            ax.set_xlabel("target event rate (achieved)")
            if ylog:
                ax.set_yscale("log")
            if ylim:
                ax.set_ylim(*ylim)
        axes[0][0].set_ylabel(ylabel)
        axes[0][-1].legend(fontsize=7.5, loc="best")
        fig.suptitle(title, fontsize=10.5, y=1.0)
        self.save(fig, name)

    def overhead(self, ovh, name):
        if ovh.empty:
            return
        variants = variants_present(ovh)
        fig, ax = plt.subplots(figsize=(5.2, 3.6))
        for i, v in enumerate(variants):
            vals = ovh.loc[ovh["variant"] == v, "overhead_pct"].dropna().to_numpy(dtype=float)
            if not len(vals):
                continue
            ax.bar(i, vals.mean(), yerr=vals.std(ddof=1) if len(vals) > 1 else 0, capsize=4,
                   color=COLORS.get(v, "gray"), alpha=0.75)
            ax.scatter([i] * len(vals), vals, color="black", s=10, zorder=3)
        ax.axhline(0, color="black", lw=0.8)
        ax.set_xticks(range(len(variants)))
        ax.set_xticklabels([SHORT.get(v, v) for v in variants])
        ax.set_ylabel("slowdown of the benign compile (%)")
        ax.set_title("Application overhead of monitoring (mean ± std, dots = single runs)", fontsize=9.5)
        self.save(fig, name)

    def sampling_effect(self, runs, name):
        sub = runs[runs["variant"].isin(["prio", "priosamp"])]
        if sub["variant"].nunique() < 2:
            return
        panels = [("total_loss_pct", "events lost in the buffer (%)"),
                  ("unseen_pct", "events not seen: lost + sampled out (%)"),
                  ("critical_loss_pct", "critical (high-priority) loss (%)"),
                  ("detection_rate_pct", "detection rate (%)"),
                  ("consumer_cpu_pct", "consumer CPU (% of one core)"),
                  ("latency_ms", "detection latency (ms)")]
        rates = rates_present(sub)
        fig, axes = plt.subplots(2, 3, figsize=(11, 6))
        w = 0.38
        for ax, (m, lab) in zip(axes.flat, panels):
            for j, v in enumerate(["prio", "priosamp"]):
                g = sub[sub["variant"] == v].groupby("rate")[m]
                mu = [g.mean().get(r, np.nan) for r in rates]
                sd = [np.nan_to_num(g.std().get(r, np.nan)) for r in rates]
                ax.bar(np.arange(len(rates)) + (j - 0.5) * w, mu, w, yerr=sd, capsize=3,
                       color=COLORS[v], alpha=0.8, label=SHORT[v])
            ax.set_xticks(range(len(rates)))
            ax.set_xticklabels([fmt_rate(r) for r in rates])
            ax.set_xlabel("target event rate")
            ax.set_ylabel(lab, fontsize=8)
            if m in ("detection_rate_pct",):
                ax.set_ylim(0, 105)
        axes[0][0].legend(fontsize=8)
        fig.suptitle("Adaptive sampling on vs off (priority design, averaged over all CPU loads)", fontsize=10.5)
        self.save(fig, name)

    def detection_by_attack(self, det, name):
        if det.empty:
            return
        rate = max(set(det["rate"]), key=lambda r: (r == 0, r))      # unpaced if present
        sub = det[det["rate"] == rate]
        variants = variants_present(sub)
        fig, ax = plt.subplots(figsize=(6.4, 3.6))
        w = 0.8 / max(len(variants), 1)
        for i, v in enumerate(variants):
            g = sub[sub["variant"] == v].groupby("attack")[["detected", "injected"]].sum()
            vals = [100.0 * g.loc[a, "detected"] / g.loc[a, "injected"] if a in g.index else np.nan
                    for a in ATTACKS]
            ax.bar(np.arange(len(ATTACKS)) + (i - (len(variants) - 1) / 2) * w, vals, w,
                   color=COLORS.get(v, "gray"), label=SHORT.get(v, v), alpha=0.85)
        ax.set_xticks(range(len(ATTACKS)))
        ax.set_xticklabels(ATTACKS)
        ax.set_ylim(0, 105)
        ax.set_ylabel("detection rate (%)")
        ax.set_title(f"Detection per attack at the highest event rate ({fmt_rate(rate)}, all CPU loads pooled)",
                     fontsize=9.5)
        ax.legend(fontsize=8, ncol=2)
        self.save(fig, name)

    def heatmaps(self, agg, name):
        rates, loads = rates_present(agg), loads_present(agg)
        variants = variants_present(agg)
        cols = [(r, l) for r in rates for l in loads]
        panels = [("critical_loss_pct_mean", "critical loss (%)", "viridis_r", 0, None),
                  ("total_loss_pct_mean", "total loss (%)", "viridis_r", 0, None),
                  ("detection_rate_pct_mean", "detection rate (%)", "viridis", 0, 100)]
        fig, axes = plt.subplots(len(panels), 1, figsize=(max(7, 0.55 * len(cols) + 2.5), 2.1 * len(panels) + 0.8))
        for ax, (m, title, cmap, vmin, vmax) in zip(np.atleast_1d(axes), panels):
            mat = np.full((len(variants), len(cols)), np.nan)
            for i, v in enumerate(variants):
                for j, (r, l) in enumerate(cols):
                    row = agg[(agg["variant"] == v) & (agg["rate"] == r) & (agg["cpu_load"] == l)]
                    if len(row):
                        mat[i, j] = row.iloc[0][m]
            im = ax.imshow(mat, aspect="auto", cmap=cmap, vmin=vmin, vmax=vmax)
            ax.set_yticks(range(len(variants)))
            ax.set_yticklabels([SHORT.get(v, v) for v in variants])
            ax.set_xticks(range(len(cols)))
            ax.set_xticklabels([f"{fmt_rate(r)}\n{l}%" if str(l).isdigit() else f"{fmt_rate(r)}\nLLM"
                                for r, l in cols], fontsize=6.5)
            ax.grid(False)
            ax.set_title(title, fontsize=9)
            for i in range(mat.shape[0]):
                for j in range(mat.shape[1]):
                    if not np.isnan(mat[i, j]):
                        rgb = im.cmap(im.norm(mat[i, j]))[:3]
                        lum = 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2]
                        ax.text(j, i, f"{mat[i, j]:.0f}", ha="center", va="center", fontsize=6,
                                color="black" if lum > 0.5 else "white")
            fig.colorbar(im, ax=ax, fraction=0.02, pad=0.01)
        fig.suptitle("Every configuration at a glance (columns: target rate / CPU load)", fontsize=10.5)
        self.save(fig, name)


# --------------------------------------------------------------------------
# tables and hypothesis checks
# --------------------------------------------------------------------------
def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def pressure_subset(runs):
    """Highest event rate (unpaced if present) at the highest numeric CPU load."""
    rate = max(set(runs["rate"]), key=lambda r: (r == 0, r))
    loads = [l for l in set(runs["cpu_load"]) if str(l).isdigit()]
    load = max(loads, key=int) if loads else sorted(set(runs["cpu_load"]))[-1]
    return runs[(runs["rate"] == rate) & (runs["cpu_load"] == load)], rate, load


def stat_table(sub, variants):
    rows = []
    for v in variants:
        s = sub[sub["variant"] == v]
        if s.empty:
            continue
        f = lambda c, d=2: pm(s[c].mean(), s[c].std(ddof=1) if len(s) > 1 else 0, d)  # noqa: E731
        rows.append([SHORT.get(v, v), len(s), f("achieved_rate", 0), f("total_loss_pct"), f("critical_loss_pct"),
                     f("sampled_pct"), f("ordering_acc_pct"), f("detection_rate_pct", 1), f("latency_ms", 1),
                     f("consumer_cpu_pct", 1)])
    header = ["Design", "runs", "events/s", "total loss %", "critical loss %", "sampled out %",
              "ordering acc. %", "detection %", "latency ms", "consumer CPU %"]
    return md_table(header, rows)


def results_markdown(runs, ovh, agg, det):
    parts = []
    syn = bool(runs["fake"].any())
    if syn:
        parts.append("> **WARNING: synthetic test data. Do not put these numbers in the report.**\n")
    for mem_b in sorted(set(runs["mem_bytes"])):
        r = runs[runs["mem_bytes"] == mem_b]
        mem = human_bytes(mem_b)
        variants = variants_present(r)
        n_cfg = r.groupby(["variant", "rate", "cpu_load"]).ngroups
        parts.append(f"## Buffer memory budget: {mem}\n")
        parts.append(f"{len(r)} runs, {n_cfg} configurations, "
                     f"{int(r.groupby(['variant', 'rate', 'cpu_load']).size().min())}-"
                     f"{int(r.groupby(['variant', 'rate', 'cpu_load']).size().max())} repeats each. "
                     "Values are mean ± std over the runs.\n")
        mxr = max(set(r['rate']), key=lambda x: (x == 0, x))
        for rate, load in config_list(r):
            sub = r[(r['rate'] == rate) & (r['cpu_load'] == load)]
            parts.append(f"### {config_title(rate, load, mxr)}\n")
            parts.append(stat_table(sub, variants) + "\n")
        parts.append("### Mean over every configuration\n")
        parts.append(stat_table(r, variants) + "\n")
        rates = rates_present(r)
        ach = [[fmt_rate(x) if x else "max", f"{r.loc[r['rate'] == x, 'achieved_rate'].median():,.0f}"]
               for x in rates]
        parts.append("### Target vs achieved event rate (median over runs)\n")
        parts.append(md_table(["target rate", "achieved events/s"], ach) + "\n")
        o = ovh[ovh["mem_bytes"] == mem_b] if not ovh.empty else ovh
        if not o.empty:
            rows = []
            for v in variants_present(o):
                s = o[o["variant"] == v]
                rows.append([SHORT.get(v, v), len(s), pm(s["baseline_s"].mean(), s["baseline_s"].std(ddof=1) if len(s) > 1 else 0, 2),
                             pm(s["monitored_s"].mean(), s["monitored_s"].std(ddof=1) if len(s) > 1 else 0, 2),
                             pm(s["overhead_pct"].mean(), s["overhead_pct"].std(ddof=1) if len(s) > 1 else 0, 2),
                             pm(s["consumer_cpu_pct"].mean(), s["consumer_cpu_pct"].std(ddof=1) if len(s) > 1 else 0, 1),
                             int(s["false_alerts"].sum())])
            parts.append("### Application overhead (benign compile with and without monitoring)\n")
            parts.append(md_table(["Design", "runs", "baseline s", "monitored s", "slowdown %",
                                   "consumer CPU %", "false alerts"], rows) + "\n")
        d = det[det["mem_bytes"] == mem_b] if not det.empty else det
        if not d.empty:
            rows = []
            for v in variants_present(d):
                row = [SHORT.get(v, v)]
                for a in ATTACKS:
                    s = d[(d["variant"] == v) & (d["attack"] == a)]
                    row.append(f"{100.0 * s['detected'].sum() / s['injected'].sum():.1f}" if len(s) else "n/a")
                rows.append(row)
            parts.append("### Detection rate per attack (%, pooled over all configurations)\n")
            parts.append(md_table(["Design"] + ATTACKS, rows) + "\n")
    return "\n".join(parts)


class Check:
    def __init__(self, hid, text, values, verdict):
        self.hid, self.text, self.values, self.verdict = hid, text, values, verdict


def config_list(runs):
    """Configurations used by the tables and the hypothesis check: highest rate at the
    lowest and highest CPU load, and the highest paced rate at the lowest load (the only
    one where every design is offered the same events/s)."""
    rates = sorted(set(runs["rate"]))
    mx = max(rates, key=lambda r: (r == 0, r))
    loads = sorted([l for l in set(runs["cpu_load"]) if str(l).isdigit()], key=int) or sorted(set(runs["cpu_load"]))
    lo, hi = loads[0], loads[-1]
    cfgs = [(mx, lo)] + ([(mx, hi)] if hi != lo else [])
    paced = [r for r in rates if r > 0]
    if paced and max(paced) != mx:
        cfgs.append((max(paced), lo))
    return cfgs


def config_title(rate, load, mx):
    kind = "Event rate max" if rate == mx else f"Highest paced event rate {fmt_rate(rate)}"
    note = " (same offered load for every design)" if rate != mx else ""
    return f"{kind}, CPU load {load}{note}"


def evaluate_hypotheses(runs, ovh, tol=1.0):
    """H1-H4 as numeric checks. Two numbers count as equal when they differ by less
    than the run-to-run spread (std), 5% or a small absolute tolerance; such cases are
    'inconclusive' and never 'supported'."""
    out = {}
    for mem_b in sorted(set(runs["mem_bytes"])):
        r = runs[runs["mem_bytes"] == mem_b]
        o = ovh[ovh["mem_bytes"] == mem_b] if not ovh.empty else ovh
        mx = max(set(r["rate"]), key=lambda x: (x == 0, x))
        for rate, load in config_list(r):
            sub = r[(r["rate"] == rate) & (r["cpu_load"] == load)]

            def m(v, col, frame=sub):
                s = frame.loc[frame["variant"] == v, col]
                return float(s.mean()) if len(s) else float("nan")

            def sd(v, col, frame=sub):
                s = frame.loc[frame["variant"] == v, col]
                return float(s.std(ddof=1)) if len(s) > 1 else 0.0

            def cmp(col, a, b, frame=sub):
                x, y = m(a, col, frame), m(b, col, frame)
                if abs(x - y) <= max(sd(a, col, frame), sd(b, col, frame), 0.05 * max(abs(x), abs(y)), 0.1):
                    return 0
                return 1 if x > y else -1

            def extreme(v, col, highest, others=CORE):
                res = [cmp(col, v, w) * (1 if highest else -1) for w in others if w != v]
                if all(x > 0 for x in res):
                    return "supported"
                if any(x < 0 for x in res):
                    return "not supported"
                return "inconclusive (equal to another design within the spread)"

            have = lambda *vs: all(not math.isnan(m(v, "total_loss_pct")) for v in vs)  # noqa: E731
            fmt = lambda d: ", ".join(f"{SHORT[k]} {x:.2f}" for k, x in d.items())  # noqa: E731
            checks = []
            if have(*CORE):
                ach = {v: m(v, "achieved_rate") for v in CORE + ["priosamp"] if have(v)}
                checks.append(Check("", "(context) achieved events/s", ", ".join(f"{SHORT[k]} {x:.0f}" for k, x in ach.items()), "info"))
                uneq = (" (caution: the designs carried unequal event rates)"
                        if min(ach[v] for v in CORE) < 0.8 * max(ach[v] for v in CORE) else "")
                ordr = {v: m(v, "ordering_acc_pct") for v in CORE}
                loss = {v: m(v, "total_loss_pct") for v in CORE}
                crit = {v: m(v, "critical_loss_pct") for v in CORE}
                cpu = {v: m(v, "consumer_cpu_pct") for v in CORE}
                ooo = {v: m(v, "ooo_critical") for v in CORE}
                nolo = max(loss.values()) < 0.5
                nt = "not testable (no overload: all designs lost < 0.5%)"
                c = cmp("ordering_acc_pct", "fifo", "percpu")
                checks.append(Check("H1", "FIFO keeps events in order better than per-CPU (ordering accuracy %)", fmt(ordr),
                                    "supported" if c > 0 else ("not supported" if c < 0 else "inconclusive")))
                checks.append(Check("H1", "FIFO has the best ordering accuracy of the three designs", fmt(ordr),
                                    extreme("fifo", "ordering_acc_pct", True)))
                checks.append(Check("H1", "FIFO has the highest total loss (%)", fmt(loss),
                                    (nt if nolo else extreme("fifo", "total_loss_pct", True)) + (uneq if not nolo else "")))
                checks.append(Check("H1", "FIFO has the highest loss of critical (high-priority) events (%)", fmt(crit),
                                    (nt if nolo else extreme("fifo", "critical_loss_pct", True)) + (uneq if not nolo else "")))
                checks.append(Check("H1", "FIFO has the highest consumer CPU (% of one core)", fmt(cpu),
                                    extreme("fifo", "consumer_cpu_pct", True)))
                checks.append(Check("H2", "Per-CPU has the lowest total loss (%)", fmt(loss),
                                    (nt if nolo else extreme("percpu", "total_loss_pct", False)) + (uneq if not nolo else "")))
                checks.append(Check("H2", "Per-CPU has the lowest ordering accuracy (%)", fmt(ordr),
                                    extreme("percpu", "ordering_acc_pct", False)))
                checks.append(Check("H2", "Per-CPU has the most out-of-order events inside detected attack sequences", fmt(ooo),
                                    "not testable (no design had out-of-order events inside detected attacks)" if max(ooo.values()) == 0
                                    else extreme("percpu", "ooo_critical", True)))
                if loss["prio"] < 10:
                    v3 = f"not testable (priority design lost only {loss['prio']:.1f}% in total)"
                else:
                    v3 = "supported" if crit["prio"] < 1.0 else "not supported"
                checks.append(Check("H3", "Priority keeps critical loss near 0 (< 1%) while its total loss is high (>= 10%)",
                                    f"critical loss {crit['prio']:.2f}%, total loss {loss['prio']:.2f}%", v3))
                for w, nm in (("fifo", "FIFO"), ("percpu", "per-CPU")):
                    c = cmp("critical_loss_pct", "prio", w)
                    checks.append(Check("H3", f"Priority loses fewer critical events than {nm} (%)",
                                        f"Priority {crit['prio']:.2f}, {SHORT[w]} {crit[w]:.2f}",
                                        nt if nolo else ("supported" if c < 0 else ("not supported" if c > 0 else
                                                          "inconclusive (equal within the spread)"))))
                checks.append(Check("H3", "Cost: latency for low-priority events", "not measured (only detection latency is)", "not measured"))
            if have("prio", "priosamp"):
                dr = {v: m(v, "detection_rate_pct") for v in ("prio", "priosamp")}
                checks.append(Check("H4", "Sampling does not reduce the detection rate", fmt(dr),
                                    "supported" if dr["priosamp"] >= dr["prio"] - tol else "not supported"))
                lo = {v: m(v, "total_loss_pct") for v in ("prio", "priosamp")}
                un = {v: m(v, "unseen_pct") for v in ("prio", "priosamp")}
                c = cmp("total_loss_pct", "priosamp", "prio")
                checks.append(Check("H4", "Sampling reduces events lost in the buffer (%)", fmt(lo),
                                    "not testable (priority design already lost < 0.5%)" if lo["prio"] < 0.5
                                    else ("supported" if c < 0 else ("not supported" if c > 0 else "inconclusive (equal within the spread)"))))
                checks.append(Check("H4", "(context) events not seen, including those sampled out on purpose (%)", fmt(un), "info"))
                cp = {v: m(v, "consumer_cpu_pct") for v in ("prio", "priosamp")}
                c = cmp("consumer_cpu_pct", "priosamp", "prio")
                checks.append(Check("H4", "Sampling reduces consumer CPU (% of one core)", fmt(cp),
                                    "supported" if c < 0 else ("not supported" if c > 0 else "inconclusive (equal within the spread)")))
            out[(human_bytes(mem_b), rate, load, rate == mx)] = checks
        if not o.empty and set(CORE) <= set(o["variant"]):
            s = {v: o.loc[o["variant"] == v, "overhead_pct"] for v in o["variant"].unique()}
            mean = {v: float(x.mean()) for v, x in s.items()}
            std = {v: float(x.std(ddof=1)) if len(x) > 1 else 0.0 for v, x in s.items()}
            eq = lambda a, b: abs(mean[a] - mean[b]) <= max(std[a], std[b], 0.5)  # noqa: E731
            f1 = ("supported" if all(mean["fifo"] > mean[w] and not eq("fifo", w) for w in ("percpu", "prio"))
                  else ("inconclusive (equal to another design within the spread)" if any(eq("fifo", w) for w in ("percpu", "prio"))
                        else "not supported"))
            out[(human_bytes(mem_b), None, "overhead", False)] = [
                Check("H1", "FIFO has the highest application slowdown (%)", ", ".join(f"{SHORT[v]} {mean[v]:.2f} ± {std[v]:.2f}" for v in mean), f1)]
    return out


def hypotheses_markdown(results, synthetic):
    parts = ["# Automatic check of H1-H4\n"]
    if synthetic:
        parts.append("> **WARNING: synthetic test data.**\n")
    parts.append("Each table compares the designs in one configuration, using the mean over all repeats. Two numbers count as "
                 "equal if they differ by less than the run-to-run spread (standard deviation), a small absolute tolerance or 5%; "
                 "such cases are marked inconclusive and never as supported. At an unpaced rate the designs do not carry the same "
                 "number of events per second, so loss comparisons there carry a caution; the paced rate is the like-for-like "
                 "comparison. The verdicts are a starting point: read the numbers and the graphs before writing a conclusion.\n")
    for (mem, rate, load, is_max), checks in results.items():
        if rate is None:
            parts.append(f"## Memory {mem}: application overhead (benign compile)\n")
        else:
            parts.append(f"## Memory {mem}: {config_title(rate, load, is_max)}\n")
        parts.append(md_table(["", "Check", "Measured", "Verdict"], [[c.hid, c.text, c.values, c.verdict] for c in checks]) + "\n")
    return "\n".join(parts)


def update_readme(path, runs, agg):
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    start, end = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
    if start not in text or end not in text:
        warn(f"{path} has no {start} ... {end} block, README not changed")
        return False
    mem_b = min(set(runs["mem_bytes"]))
    r = runs[runs["mem_bytes"] == mem_b]
    mxr = max(set(r["rate"]), key=lambda x: (x == 0, x))
    cfgs = config_list(r)
    pick = [cfgs[0]] + ([cfgs[-1]] if len(cfgs) > 1 and cfgs[-1][0] != mxr else [])
    body = ""
    for rate, load in pick:
        sub = r[(r["rate"] == rate) & (r["cpu_load"] == load)]
        body += f"**{config_title(rate, load, mxr)}**\n\n" + stat_table(sub, variants_present(sub)) + "\n\n"
    block = (f"{start}\n"
             f"Buffer memory {human_bytes(mem_b)}, mean ± std over the repeats. "
             "All graphs and tables: [`analysis/figures/`](analysis/figures/), "
             "numbers in [`analysis/figures/results_tables.md`](analysis/figures/results_tables.md).\n\n"
             + body.rstrip() + "\n"
             f"{end}")
    new = re.sub(re.escape(start) + r".*?" + re.escape(end), lambda _: block, text, flags=re.S)
    path.write_text(new, encoding="utf-8")
    return True


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Part 6: tables and graphs from results/")
    ap.add_argument("results", nargs="+",
                    help="folder(s) with one sub-folder per run (e.g. results/ results_4m/)")
    ap.add_argument("--out", default="analysis/figures", help="where to write graphs and tables")
    ap.add_argument("--pdf", action="store_true", help="also write each graph as PDF")
    ap.add_argument("--dpi", type=int, default=160)
    ap.add_argument("--include-incomplete", action="store_true", help="also use runs without a .complete marker")
    ap.add_argument("--update-readme", nargs="?", const="README.md", metavar="FILE",
                    help="refresh the RESULTS block in FILE (default README.md)")
    args = ap.parse_args()

    runs, ovh, det = load_results(args.results, args.include_incomplete)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    synthetic = bool(runs["fake"].any())
    if synthetic:
        warn("these results are marked synthetic (fake): graphs get a watermark, do not use them in the report")

    agg = aggregate(runs)
    runs.sort_values(["mem_bytes", "variant", "rate", "cpu_load", "rep"]).to_csv(out / "runs.csv", index=False)
    agg.to_csv(out / "summary_by_config.csv", index=False)
    if not det.empty:
        det.to_csv(out / "detection_by_attack.csv", index=False)
    if not ovh.empty:
        ovh.to_csv(out / "overhead.csv", index=False)

    plotter = Plotter(out, args.pdf, args.dpi, synthetic)
    for mem_b in sorted(set(runs["mem_bytes"])):
        suffix = f"_mem{human_bytes(mem_b)}" if runs["mem_bytes"].nunique() > 1 else ""
        r, a = runs[runs["mem_bytes"] == mem_b], agg[agg["mem_bytes"] == mem_b]
        memlabel = f"buffer memory {human_bytes(mem_b)}"
        plotter.lines(a, r, "total_loss_pct", "events lost (% of emitted)", f"fig_total_loss{suffix}",
                      f"Total event loss ({memlabel})", ylim=(-2, 102))
        plotter.lines(a, r, "critical_loss_pct", "critical events lost (%)", f"fig_critical_loss{suffix}",
                      f"Loss of high-priority events: exec, fork, setuid, rename, unlink ({memlabel})", ylim=(-2, 102))
        plotter.lines(a, r, "ordering_acc_pct", "events received in kernel order (%)", f"fig_ordering{suffix}",
                      f"Ordering accuracy on arrival, before the reorder buffer ({memlabel})", ylim=(-2, 102))
        plotter.lines(a, r, "ooo_critical", "out-of-order events in detected attacks", f"fig_ooo_critical{suffix}",
                      f"Out-of-order events inside detected attack sequences ({memlabel})")
        plotter.lines(a, r, "detection_rate_pct", "injected attacks detected (%)", f"fig_detection_rate{suffix}",
                      f"Detection rate against the injected ground truth ({memlabel})", ylim=(-2, 102))
        plotter.lines(a, r, "latency_ms", "alert time - first event of attack (ms)", f"fig_latency{suffix}",
                      f"Detection latency of detected attacks ({memlabel})", ylog=True)
        plotter.lines(a, r, "consumer_cpu_pct", "consumer CPU (% of one core)", f"fig_consumer_cpu{suffix}",
                      f"CPU cost of the monitoring pipeline ({memlabel})")
        plotter.lines(a, r, "achieved_rate", "events per second actually carried", f"fig_achieved_rate{suffix}",
                      f"Event rate each design really carried ({memlabel})", ylog=True)
        plotter.heatmaps(a, f"fig_heatmap{suffix}")
        plotter.sampling_effect(r, f"fig_sampling_effect{suffix}")
        plotter.detection_by_attack(det[det["mem_bytes"] == mem_b] if not det.empty else det,
                                    f"fig_detection_by_attack{suffix}")
        if not ovh.empty:
            plotter.overhead(ovh[ovh["mem_bytes"] == mem_b], f"fig_overhead{suffix}")

    (out / "results_tables.md").write_text(results_markdown(runs, ovh, agg, det), encoding="utf-8")
    hyp = evaluate_hypotheses(runs, ovh)
    (out / "hypotheses.md").write_text(hypotheses_markdown(hyp, synthetic), encoding="utf-8")
    if args.update_readme and synthetic:
        warn("synthetic data: README NOT updated")
    elif args.update_readme:
        if update_readme(args.update_readme, runs, agg):
            print(f"updated results block in {args.update_readme}")

    print(f"\n{len(runs)} main runs, {len(ovh)} overhead runs, "
          f"{agg.shape[0]} configurations, memory budgets: {', '.join(human_bytes(m) for m in sorted(set(runs['mem_bytes'])))}")
    print(f"wrote {len(plotter.written)} graphs + tables to {out}/")
    for (mem, rate, load, _), checks in hyp.items():
        print(f"\nhypothesis check (memory {mem}, rate {fmt_rate(rate) if rate is not None else '-'}, CPU load {load}):")
        for c in checks:
            if c.verdict != "info":
                print(f"  {c.hid}  {c.verdict:<14} {c.text}")


if __name__ == "__main__":
    main()
