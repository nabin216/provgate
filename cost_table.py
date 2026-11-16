"""Overhead of the defences: latency, gateway time and LLM tokens per episode.

    python cost_table.py                       # all models, all configs, all attacks
    python cost_table.py --configs B0 B2 G3 G4 G5 --attack important_instructions

Reads the existing run logs (runs/<model>/<config>/<attack>/rep0.jsonl); no API
calls. Episodes with LLM errors are left out. 'Gateway ms' is the time spent
inside the gateway's own checks; 'wall s' is the whole episode including the
LLM API, so it also varies with provider load. Token and LLM-call ratios are
relative to B0 on the same model and attack.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics as st
from collections import defaultdict
from pathlib import Path

ORDER = ["B0", "B1", "B2", "B3", "B4", "G1", "G1-M3", "G3", "G3+", "G4", "G4-M3", "G4+", "G4-noC2",
         "G4-deny", "G5", "G5-deny"]


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))] if xs else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--configs", nargs="*")
    ap.add_argument("--attack", nargs="*", help="attack names (default: all, incl. benign)")
    ap.add_argument("--out", default="results/cost_table.csv")
    a = ap.parse_args()

    data = defaultdict(list)   # (model, config, attack) -> rows
    for f in Path(a.runs).glob("*/*/*/rep0.jsonl"):
        model, cfg, attack = f.parts[-4], f.parts[-3], f.parts[-2]
        if a.configs and cfg not in a.configs:
            continue
        if a.attack and attack not in a.attack:
            continue
        for line in f.read_text().splitlines():
            r = json.loads(line)
            if r.get("llm_errors", 0) or r.get("error"):
                continue
            data[(model, cfg, attack)].append(r)

    out = []
    for model in sorted({k[0] for k in data}):
        for attack in sorted({k[2] for k in data if k[0] == model}):
            cfgs = [c for c in ORDER if (model, c, attack) in data] + \
                   sorted(c for (m, c, t) in data if m == model and t == attack and c not in ORDER)
            base = data.get((model, "B0", attack), [])
            b_tok = st.mean([r["prompt_tokens"] + r["completion_tokens"] for r in base]) if base else None
            b_calls = st.mean([r["llm_calls"] for r in base]) if base else None
            b_wall = st.median([r["wall_s"] for r in base]) if base else None
            print(f"\n=== {model} | {attack}")
            print(f"{'config':9}{'n':>6}{'wall s med':>12}{'p95':>8}{'gw ms/ep':>10}{'gw ms/call':>12}"
                  f"{'gw p95':>9}{'LLM calls':>11}{'tokens':>10}{'tok/B0':>8}{'wall/B0':>9}")
            for c in cfgs:
                rows = data[(model, c, attack)]
                wall = [r["wall_s"] for r in rows]
                gw = [r.get("gateway_ms", 0.0) for r in rows]
                ncalls = sum(r.get("tool_calls", 0) for r in rows)
                tok = [r["prompt_tokens"] + r["completion_tokens"] for r in rows]
                calls = [r["llm_calls"] for r in rows]
                row = {
                    "model": model, "attack": attack, "config": c, "n": len(rows),
                    "wall_s_median": round(st.median(wall), 2), "wall_s_p95": round(p95(wall), 2),
                    "gateway_ms_mean": round(st.mean(gw), 2), "gateway_ms_p95": round(p95(gw), 2),
                    "gateway_ms_per_tool_call": round(sum(gw) / ncalls, 3) if ncalls else 0.0,
                    "llm_calls_mean": round(st.mean(calls), 2), "tokens_mean": round(st.mean(tok)),
                    "tokens_vs_B0": round(st.mean(tok) / b_tok, 2) if b_tok else None,
                    "llm_calls_vs_B0": round(st.mean(calls) / b_calls, 2) if b_calls else None,
                    "wall_vs_B0": round(st.median(wall) / b_wall, 2) if b_wall else None,
                }
                out.append(row)
                print(f"{c:9}{row['n']:>6}{row['wall_s_median']:>12}{row['wall_s_p95']:>8}"
                      f"{row['gateway_ms_mean']:>10}{row['gateway_ms_per_tool_call']:>12}{row['gateway_ms_p95']:>9}"
                      f"{row['llm_calls_mean']:>11}{row['tokens_mean']:>10}"
                      f"{str(row['tokens_vs_B0'] or '-'):>8}{str(row['wall_vs_B0'] or '-'):>9}")
    if out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        with open(a.out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(out[0]))
            w.writeheader()
            w.writerows(out)
        print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
