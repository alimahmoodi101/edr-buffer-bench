#!/usr/bin/env python3
"""check_attacks.py - did the traced events capture each injected attack?

    python3 workloads/check_attacks.py results/<run>/

Reads <run>/injections.csv (ground truth) and <run>/events.csv (written by
`edr_consumer --events` or `evdump --csv`) and, for every injection, counts
the events the detector rules in docs/CONTRACT.md section 5 look at:

    ransomware  rename + unlink by that tgid      (rule needs >= 50 in 5 s)
    forkstorm   fork by that tgid, best 1 s window (rule needs >= 100 in 1 s)
    privesc     setuid(0) then exec of a shell     (within 2 s)

This is a sanity check for Part 2 (are the attacks visible at all?), not
the detector. It uses only the standard library.
"""
import csv
import os
import sys
from bisect import bisect_left, bisect_right
from collections import defaultdict

SHELLS = ("sh", "bash", "dash", "zsh")
SEC = 1_000_000_000


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run = sys.argv[1]
    try:
        inj = list(csv.DictReader(open(os.path.join(run, "injections.csv"))))
        ev_file = open(os.path.join(run, "events.csv"))
    except OSError as e:
        sys.exit(f"check_attacks: {e}")

    # keep only the event types the rules use, grouped by tgid
    wanted = {"rename", "unlink", "fork", "setuid", "exec"}
    by_tgid = defaultdict(list)          # tgid -> [(ts, type, arg1, path)]
    for row in csv.DictReader(ev_file):
        if row["type"] in wanted:
            by_tgid[int(row["tgid"])].append(
                (int(row["ts_ns"]), row["type"], int(row["arg1"]), row["path"]))
    for evs in by_tgid.values():
        evs.sort()

    missed = 0
    print(f"{'attack':<11} {'tgid':>7}  {'dur ms':>7}  result")
    for i in inj:
        tgid, start, end = int(i["tgid"]), int(i["start_ns"]), int(i["end_ns"])
        evs = [e for e in by_tgid.get(tgid, []) if start <= e[0] <= end + 5 * SEC]
        a = i["attack"]
        if a == "ransomware":
            n = sum(1 for e in evs if e[1] in ("rename", "unlink"))
            ok, what = n >= 50, f"{n} rename/unlink"
        elif a == "forkstorm":
            ts = [e[0] for e in evs if e[1] == "fork"]
            best = max((bisect_right(ts, t + SEC) - bisect_left(ts, t) for t in ts), default=0)
            ok, what = best >= 100, f"{best} forks in best 1 s window ({len(ts)} total)"
        elif a == "privesc":
            su = [e[0] for e in evs if e[1] == "setuid" and e[2] == 0]
            ex = [e[0] for e in evs if e[1] == "exec"
                  and os.path.basename(e[3]) in SHELLS]
            ok = any(0 <= x - s <= 2 * SEC for s in su for x in ex)
            what = f"{len(su)} setuid(0), {len(ex)} shell exec"
        else:
            ok, what = False, "unknown attack type"
        missed += not ok
        print(f"{a:<11} {tgid:>7}  {(end - start) / 1e6:>7.1f}  "
              f"{'OK    ' if ok else 'MISSED'} {what}")

    print(f"\n{len(inj) - missed}/{len(inj)} injections visible in events.csv")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
