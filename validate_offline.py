"""Compare the live pipeline (scripted worst-case agent) with the RQ1 replay.

    python run_live.py --model scripted --configs B0 G1 G2 G3-deny G4-deny --benign --attack <each of 6 attacks>
    python validate_offline.py --runs runs --replay ../prototype/results/summary.json

The replay counts an attempt as successful if every malicious call is allowed, so
its no-defence ASR is 100% by construction. In the live pipeline an attack is
scored by AgentDojo's own security check, which a few injection tasks fail even
with no defence (no ground truth, or checks that also match the injected text).
To compare like with like, live ASR here is computed over the pairs where the
undefended attack succeeded (B0 security = True).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from statsmodels.stats.proportion import proportion_confint

MAP = {"G1": "G1 Detection (C1)", "G2": "G2 Tool allow-list (C3a)",
       "G3-deny": "G3 Allow-list + provenance (C3)", "G4-deny": "G4 Full gateway (C1+C3+C4)"}


def load(path: Path):
    out = defaultdict(dict)
    for f in path.glob("scripted/*/*/rep0.jsonl"):
        cfg, mode = f.parts[-3], f.parts[-2]
        for line in f.read_text().splitlines():
            r = json.loads(line)
            out[(cfg, mode)][(r["suite"], r["user_task"], r["injection_task"])] = r
    return out


def pct(k, n):
    lo, hi = proportion_confint(k, n, method="wilson") if n else (0, 0)
    return f"{100 * k / n:5.1f}% [{100 * lo:.1f}-{100 * hi:.1f}]" if n else "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--replay", default=None)
    ap.add_argument("--out", default="results/offline_validation.md")
    a = ap.parse_args()
    data = load(Path(a.runs))
    replay = json.loads(Path(a.replay).read_text())["exp2"] if a.replay else {}
    attacks = sorted({m for (_, m) in data if m != "benign"})
    lines = ["# Offline validation: live pipeline vs RQ1 replay", "",
             "Scripted worst-case agent through the real AgentDojo pipeline (no LLM).",
             "Live ASR is over pairs where the undefended attack succeeded (B0).", ""]

    b0 = {}
    for m in attacks:
        b0.update({(m, *k): r for k, r in data.get(("B0", m), {}).items()})
    base = {k for k, r in b0.items() if r["security"]}
    lines += [f"Attack pairs run: {len(b0)}; succeeded with no defence: {len(base)}", "",
              "| Config | Live ASR (all 6 attacks) | Replay ASR | Live benign utility | Replay benign uninterrupted |",
              "|---|---|---|---|---|"]
    for cfg in ["G1", "G2", "G3-deny", "G4-deny"]:
        rows = {(m, *k): r for m in attacks for k, r in data.get((cfg, m), {}).items()}
        common = [k for k in base if k in rows]
        k_succ = sum(rows[k]["security"] for k in common)
        ben = list(data.get((cfg, "benign"), {}).values())
        rp = replay.get(MAP[cfg], {})
        lines.append(f"| {cfg} | {pct(k_succ, len(common))} (n={len(common)}) | "
                     f"{100 * rp.get('ASR', float('nan')):.1f}% | "
                     f"{pct(sum(r['utility'] for r in ben), len(ben))} | "
                     f"{100 * rp.get('benign_uninterrupted', float('nan')):.1f}% |")
    lines += ["", "## By attack style (live ASR over B0-successful pairs)", "",
              "| Attack | n | " + " | ".join(MAP) + " |", "|---|---|" + "---|" * len(MAP)]
    for m in attacks:
        ks = [k for k in base if k[0] == m]
        cells = []
        for cfg in MAP:
            rows = data.get((cfg, m), {})
            c = [k for k in ks if k[1:] in rows]
            cells.append(f"{100 * sum(rows[k[1:]]['security'] for k in c) / len(c):.1f}" if c else "-")
        lines.append(f"| {m} | {len(ks)} | " + " | ".join(cells) + " |")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
