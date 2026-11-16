"""RQ4 table: attack success by adaptive-attack category and configuration.

    python rq4_table.py                                  # live runs in runs/
    python rq4_table.py --runs runs_offline --scripted   # scripted worst-case agent

Categories (live/rq4.py): A1 framing-free payloads on the 35 original injection
tasks; A2 argument manipulation (new tasks); A3 the A1 pairs whose injected
write tools are all tools the user task itself needs; A4 object-level goals.
With --scripted, ASR is over the pairs on which the undefended attack (B0)
succeeds, as in validate_mitigations.py; live, over all pairs.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites
from statsmodels.stats.proportion import proportion_confint

from gateway.policy import CATALOGUE
from live import rq4

ORDER = ["B0", "B2", "B3", "B4", "G1", "G3", "G3+", "G4", "G4+", "G5", "G5-deny"]
CATS = ["A1", "A2", "A3", "A4"]
NAMES = {"A1": "A1 framing-free payloads", "A2": "A2 argument manipulation",
         "A3": "A3 tool reuse", "A4": "A4 object-level goals"}


def write_tools(calls) -> set[str]:
    return {c.function for c in calls if c.function in CATALOGUE and CATALOGUE[c.function].write}


def categories():
    suites = get_suites("v1.2")
    rq4.install(suites)
    out = {}
    for sname, suite in suites.items():
        env = suite.load_and_inject_default_environment({})
        uw = {u: write_tools(t.ground_truth(env.model_copy(deep=True))) for u, t in suite.user_tasks.items()}
        iw = {i: write_tools(t.ground_truth(env.model_copy(deep=True))) for i, t in suite.injection_tasks.items()}
        for u in uw:
            for i in iw:
                out[(sname, u, i)] = rq4.category(sname, i, uw[u], iw[i])
    return out


def pct(k, n):
    if not n:
        return "-"
    lo, hi = proportion_confint(k, n, method="wilson")
    return f"{100 * k / n:.1f} [{100 * lo:.1f}-{100 * hi:.1f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--scripted", action="store_true")
    ap.add_argument("--attack", default="rq4_plain")
    a = ap.parse_args()
    cats = categories()
    data = defaultdict(dict)   # (model, config) -> key -> row
    for f in Path(a.runs).glob(f"*/*/{a.attack}/rep0.jsonl"):
        for line in f.read_text().splitlines():
            r = json.loads(line)
            data[(r["model"], r["config"])][(r["suite"], r["user_task"], r["injection_task"])] = r
    for model in sorted({m for m, _ in data}):
        cfgs = [c for c in ORDER if (model, c) in data] + sorted(c for m, c in data if m == model and c not in ORDER)
        b0 = data.get((model, "B0"), {})
        print(f"\n=== {model}  ({'scripted worst-case agent: ASR over pairs B0 hijacks' if a.scripted else 'live: ASR over all pairs'})")
        print(f"{'category':28}" + "".join(f"{c:>20}" for c in cfgs))
        for cat in CATS:
            cells = []
            for c in cfgs:
                rows = data[(model, c)]
                keys = [k for k in rows if cat in cats.get(k, [])]
                if a.scripted:
                    keys = [k for k in keys if b0.get(k, {}).get("security")]
                k_s = sum(bool(rows[k]["security"]) for k in keys)
                cells.append(f"{pct(k_s, len(keys)) + f' n={len(keys)}':>20}" if keys else f"{'-':>20}")
            print(f"{NAMES[cat]:28}" + "".join(cells))
        print("\nutility under attack (all rq4 pairs):")
        for c in cfgs:
            rows = data[(model, c)]
            print(f"  {c:10} {pct(sum(bool(r['utility']) for r in rows.values()), len(rows))} n={len(rows)}")
        # which A2/A4 tasks get through the recommended configuration
        for c in [c for c in ("G5", "G3") if (model, c) in data]:
            rows = data[(model, c)]
            hits = defaultdict(int)
            for k, r in rows.items():
                if r["security"] and any(x in cats.get(k, []) for x in ("A2", "A4")):
                    hits[(k[0], k[2])] += 1
            if hits:
                print(f"\n{c}: successful A2/A4 attacks by injection task: " +
                      ", ".join(f"{s}/{i}: {n}" for (s, i), n in sorted(hits.items())))


if __name__ == "__main__":
    main()
