"""Per-suite breakdown of live results: where do attacks get through, and where is utility lost?

    python breakdown.py                       # every config, every model
    python breakdown.py --configs B0 G3 G4    # selected configs
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(ROOT / "runs"))
    ap.add_argument("--configs", nargs="*", default=None)
    a = ap.parse_args()
    data = defaultdict(list)
    for f in Path(a.runs).glob("*/*/*/rep*.jsonl"):
        if f.name.endswith((".gateway.jsonl", ".errors.jsonl")):
            continue
        for line in f.read_text().splitlines():
            r = json.loads(line)
            if a.configs and r["config"] not in a.configs:
                continue
            data[(r["model"], r["config"], r["mode"], r["suite"])].append(r)
    for model in sorted({k[0] for k in data}):
        print(f"\n=== {model}")
        modes = sorted({k[2] for k in data if k[0] == model})
        suites = sorted({k[3] for k in data if k[0] == model})
        for mode in modes:
            print(f"\n-- {mode}: " + ("utility" if mode == "benign" else "attack success / utility under attack"))
            print(f"{'config':10}" + "".join(f"{s:>22}" for s in suites))
            for cfg in sorted({k[1] for k in data if k[0] == model and k[2] == mode}):
                cells = []
                for s in suites:
                    rows = data.get((model, cfg, mode, s), [])
                    if not rows:
                        cells.append(f"{'-':>22}")
                        continue
                    n = len(rows)
                    u = sum(r["utility"] for r in rows)
                    if mode == "benign":
                        cells.append(f"{f'{u}/{n} ({100*u/n:.0f}%)':>22}")
                    else:
                        sec = sum(r["security"] for r in rows)
                        cells.append(f"{f'{sec}/{n} ({100*sec/n:.0f}%) / {100*u/n:.0f}%':>22}")
                print(f"{cfg:10}" + "".join(cells))


if __name__ == "__main__":
    main()
