"""Summarise live runs into the numbers for Table VI (and Table VIII/IX).

    python summarise_live.py                 # all models/configs under runs/
    python summarise_live.py --runs runs --compare G4 B0 G4 B3

Per model x configuration x attack it reports, with 95% Wilson intervals:
  benign utility, utility under attack, attack success rate (ASR),
  confirmations / blocked calls / quarantined outputs per episode,
  median tokens and wall time per episode.
Paired comparisons use McNemar's exact test on episodes present in both
configurations (same suite, user task, injection task, repetition), with Holm
correction. Writes results/live_summary.csv and results/live_summary.json.
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests
from statsmodels.stats.proportion import proportion_confint

ROOT = Path(__file__).resolve().parent


def wilson(k, n):
    if n == 0:
        return (float("nan"), float("nan"))
    lo, hi = proportion_confint(k, n, alpha=0.05, method="wilson")
    return (lo, hi)


def load(runs: Path):
    data = defaultdict(list)   # (model, config, mode) -> rows
    for f in runs.glob("*/*/*/rep*.jsonl"):
        if f.name.endswith((".gateway.jsonl", ".errors.jsonl")):
            continue
        for line in f.read_text().splitlines():
            r = json.loads(line)
            data[(r["model"], r["config"], r["mode"])].append(r)
    return data


def rate(rows, key):
    k = sum(bool(r[key]) for r in rows)
    n = len(rows)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "ci": [lo, hi]}


def fmt(x):
    if x["n"] == 0:
        return "-"
    return f"{100 * x['rate']:.1f} [{100 * x['ci'][0]:.1f}-{100 * x['ci'][1]:.1f}] (n={x['n']})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(ROOT / "runs"))
    ap.add_argument("--compare", nargs="*", default=None,
                    help="pairs of configs to test, e.g. G4 B0 G4 B3 (default: each of --refs vs every other)")
    ap.add_argument("--refs", nargs="*", default=["G4", "G3"],
                    help="reference configs for the default comparisons")
    ap.add_argument("--configs", nargs="*", default=None, help="only report these configs")
    args = ap.parse_args()
    data = load(Path(args.runs))
    if args.configs:
        data = {k: v for k, v in data.items() if k[1] in args.configs}
    if not data:
        raise SystemExit(f"no results under {args.runs}")

    rows_out = []
    models = sorted({m for m, _, _ in data})
    for model in models:
        configs = sorted({c for m, c, _ in data if m == model})
        attacks = sorted({a for m, _, a in data if m == model and a != "benign"})
        for c in configs:
            ben = data.get((model, c, "benign"), [])
            for a in attacks or [None]:
                att = data.get((model, c, a), []) if a else []
                allr = ben + att
                rec = {
                    "model": model, "config": c, "attack": a,
                    "benign_utility": rate(ben, "utility"),
                    "utility_under_attack": rate(att, "utility"),
                    "ASR": rate(att, "security"),
                    "confirms_per_ep": statistics.mean([r.get("confirms", 0) for r in allr]) if allr else None,
                    "blocked_per_ep": statistics.mean([r.get("blocked", 0) for r in allr]) if allr else None,
                    "quarantined_per_ep": statistics.mean([r.get("quarantined", 0) for r in allr]) if allr else None,
                    "redacted_per_ep": statistics.mean([r.get("redacted", 0) for r in allr]) if allr else None,
                    "benign_confirms_per_task": statistics.mean([r.get("confirms", 0) for r in ben]) if ben else None,
                    "median_tokens": statistics.median([r.get("prompt_tokens", 0) + r.get("completion_tokens", 0)
                                                        for r in allr]) if allr else None,
                    "median_wall_s": statistics.median([r.get("wall_s", 0) for r in allr]) if allr else None,
                    "llm_errors": sum(r.get("llm_errors", 0) for r in allr),
                }
                rows_out.append(rec)

    # paired McNemar tests
    tests = []
    for model in models:
        configs = sorted({c for m, c, _ in data if m == model})
        if args.compare:
            pairs = list(zip(args.compare[::2], args.compare[1::2]))
        else:
            pairs, seen = [], set()
            for ref in args.refs:
                if ref not in configs:
                    continue
                for c in configs:
                    if c != ref and frozenset((ref, c)) not in seen:
                        seen.add(frozenset((ref, c)))
                        pairs.append((ref, c))
        modes = sorted({a for m, _, a in data if m == model})
        for a, b in pairs:
            for mode in modes:
                ka = {(r["suite"], r["user_task"], r["injection_task"], r["rep"]): r
                      for r in data.get((model, a, mode), [])}
                kb = {(r["suite"], r["user_task"], r["injection_task"], r["rep"]): r
                      for r in data.get((model, b, mode), [])}
                common = sorted(set(ka) & set(kb))
                if not common:
                    continue
                metrics = ["utility"] if mode == "benign" else ["security", "utility"]
                for metric in metrics:
                    only_a = sum(bool(ka[k][metric]) and not bool(kb[k][metric]) for k in common)
                    only_b = sum(bool(kb[k][metric]) and not bool(ka[k][metric]) for k in common)
                    p = mcnemar([[0, only_a], [only_b, 0]], exact=True).pvalue if only_a + only_b else 1.0
                    tests.append({"model": model, "a": a, "b": b, "mode": mode, "metric": metric,
                                  "n": len(common), "only_a": only_a, "only_b": only_b, "p": p})
    if tests:
        _, p_holm, _, _ = multipletests([t["p"] for t in tests], method="holm")
        for t, ph in zip(tests, p_holm):
            t["p_holm"] = float(ph)

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "live_summary.json").write_text(json.dumps({"rows": rows_out, "tests": tests}, indent=1))
    with (out / "live_summary.csv").open("w") as f:
        f.write("model,config,attack,benign_utility,util_under_attack,ASR,confirms_per_ep,blocked_per_ep,"
                "quarantined_per_ep,redacted_per_ep,benign_confirms_per_task,median_tokens,median_wall_s,llm_errors\n")
        for r in rows_out:
            f.write(",".join(str(x) for x in [
                r["model"], r["config"], r["attack"], r["benign_utility"]["rate"],
                r["utility_under_attack"]["rate"], r["ASR"]["rate"], r["confirms_per_ep"],
                r["blocked_per_ep"], r["quarantined_per_ep"], r["redacted_per_ep"], r["benign_confirms_per_task"],
                r["median_tokens"], r["median_wall_s"],
                r["llm_errors"]]) + "\n")

    for model in models:
        print(f"\n=== {model}")
        print(f"{'config':9} {'attack':32} {'benign utility':28} {'utility under attack':30} {'ASR'}")
        for r in rows_out:
            if r["model"] == model:
                print(f"{r['config']:9} {str(r['attack']):32} {fmt(r['benign_utility']):28} "
                      f"{fmt(r['utility_under_attack']):30} {fmt(r['ASR'])}")
    if tests:
        print("\nMcNemar (exact), Holm-corrected; only_a/only_b = episodes where the metric is true only in a / b")
        print("  metric 'security' = attack succeeded; 'utility' = user task completed")
        for t in tests:
            print(f"  {t['model']}: {t['a']} vs {t['b']} [{t['mode']}, {t['metric']}] n={t['n']} "
                  f"only_a={t['only_a']} only_b={t['only_b']} p_holm={t['p_holm']:.2g}")
    print(f"\nwrote {out / 'live_summary.csv'} and live_summary.json")


if __name__ == "__main__":
    main()
