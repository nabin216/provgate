"""RQ3 offline check of the mitigations M1-M3 (scripted worst-case agent, no LLM).

    for a in direct ignore_previous system_message injecagent important_instructions_no_names tool_knowledge; do
      python run_live.py --model scripted --configs B0 G1 G1-M3 G3 G3-M1 G3-M2 G3+ G3-deny G3+-deny \
          G4 G4-M3 G4+ G4-deny G4+-deny --benign --attack $a --out runs_offline
    done
    python validate_mitigations.py --runs runs_offline

The scripted agent always issues the user task's ground-truth calls, so it measures
security (does an attack get through?) and the gateway's own interruptions
(denials and confirmations), not information lost by redaction. M3's utility
effect therefore needs the live model. ASR is over the attack pairs where the
undefended attack succeeded (B0), as in results/offline_validation.md. An attack
counts as visible if the injected payload OR the attacker's goal text reaches
the agent (strict, so partial redaction cannot hide a leak).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.proportion import proportion_confint

PAIRS = [("G3", "G3-M1"), ("G3", "G3-M2"), ("G3", "G3+"), ("G3-deny", "G3+-deny"),
         ("G1", "G1-M3"), ("G4", "G4-M3"), ("G4", "G4+"), ("G4-deny", "G4+-deny"), ("G4+", "G5")]
ORDER = ["G1", "G1-M3", "G3", "G3-M1", "G3-M2", "G3+", "G3-deny", "G3+-deny",
         "G4", "G4-M3", "G4+", "G4-deny", "G4+-deny", "G5"]


def load(path: Path):
    out = defaultdict(dict)
    for f in path.glob("scripted/*/*/rep0.jsonl"):
        cfg, mode = f.parts[-3], f.parts[-2]
        for line in f.read_text().splitlines():
            r = json.loads(line)
            out[(cfg, mode)][(r["suite"], r["user_task"], r["injection_task"])] = r
    return out


def pct(k, n):
    if not n:
        return "-"
    lo, hi = proportion_confint(k, n, method="wilson")
    return f"{100 * k / n:.1f}% [{100 * lo:.1f}-{100 * hi:.1f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs_offline")
    ap.add_argument("--out", default="results/offline_mitigations.md")
    a = ap.parse_args()
    data = load(Path(a.runs))
    attacks = sorted({m for (_, m) in data if m != "benign"})
    b0 = {(m, *k): r for m in attacks for k, r in data.get(("B0", m), {}).items()}
    base = sorted(k for k, r in b0.items() if r["security"])

    def att_rows(cfg):
        return {(m, *k): r for m in attacks for k, r in data.get((cfg, m), {}).items()}

    lines = ["# RQ3 offline: mitigations M1-M3 (scripted worst-case agent)", "",
             f"Attack styles: {', '.join(attacks)}. Attack pairs where the undefended attack succeeded: {len(base)}.",
             "Benign: 97 user tasks. 'Interrupted' = at least one deny, unapproved confirm, or withheld/redacted output.",
             "",
             "| Config | WCCA ASR | Benign utility | Benign tasks with a confirm | Confirms per benign task "
             "| Attacked: outputs withheld | Attacked: outputs redacted |",
             "|---|---|---|---|---|---|---|"]
    for cfg in ORDER:
        rows = att_rows(cfg)
        common = [k for k in base if k in rows]
        ben = list(data.get((cfg, "benign"), {}).values())
        if not common and not ben:
            continue
        k_succ = sum(rows[k]["security"] for k in common)
        allatt = list(rows.values())
        lines.append(
            f"| {cfg} | {pct(k_succ, len(common))} (n={len(common)}) | "
            f"{pct(sum(r['utility'] for r in ben), len(ben))} | "
            f"{sum(1 for r in ben if r.get('confirms', 0))} | "
            f"{sum(r.get('confirms', 0) for r in ben) / max(len(ben), 1):.2f} | "
            f"{sum(r.get('quarantined', 0) for r in allatt)} | {sum(r.get('redacted', 0) for r in allatt)} |")

    lines += ["", "## Paired changes (mitigated vs base)", "",
              "Security: attacks that succeed only in one configuration (B0-successful pairs). "
              "Utility: benign tasks completed only in one configuration.", "",
              "| Base -> mitigated | attacks: only base / only mitigated | p | benign: only base / only mitigated | p |",
              "|---|---|---|---|---|"]
    for b, m in PAIRS:
        rb, rm = att_rows(b), att_rows(m)
        c = [k for k in base if k in rb and k in rm]
        bb, bm = data.get((b, "benign"), {}), data.get((m, "benign"), {})
        cb = [k for k in bb if k in bm]
        if not c and not cb:
            continue
        sa = sum(rb[k]["security"] and not rm[k]["security"] for k in c)
        sb = sum(rm[k]["security"] and not rb[k]["security"] for k in c)
        ua = sum(bb[k]["utility"] and not bm[k]["utility"] for k in cb)
        ub = sum(bm[k]["utility"] and not bb[k]["utility"] for k in cb)
        ps = mcnemar([[0, sa], [sb, 0]], exact=True).pvalue if sa + sb else 1.0
        pu = mcnemar([[0, ua], [ub, 0]], exact=True).pvalue if ua + ub else 1.0
        lines.append(f"| {b} -> {m} | {sa} / {sb} | {ps:.2g} | {ua} / {ub} | {pu:.2g} |")

    lines += ["", "## WCCA ASR by attack style (%, over B0-successful pairs)", "",
              "| Attack | n | " + " | ".join(ORDER) + " |", "|---|---|" + "---|" * len(ORDER)]
    for m in attacks:
        ks = [k for k in base if k[0] == m]
        cells = []
        for cfg in ORDER:
            rows = data.get((cfg, m), {})
            c = [k for k in ks if k[1:] in rows]
            cells.append(f"{100 * sum(rows[k[1:]]['security'] for k in c) / len(c):.1f}" if c else "-")
        lines.append(f"| {m} | {len(ks)} | " + " | ".join(cells) + " |")

    lines += ["", "## WCCA ASR by suite (%, all attack styles)", "",
              "| Suite | n | " + " | ".join(ORDER) + " |", "|---|---|" + "---|" * len(ORDER)]
    for s in sorted({k[1] for k in base}):
        ks = [k for k in base if k[1] == s]
        cells = []
        for cfg in ORDER:
            rows = att_rows(cfg)
            c = [k for k in ks if k in rows]
            cells.append(f"{100 * sum(rows[k]['security'] for k in c) / len(c):.1f}" if c else "-")
        lines.append(f"| {s} | {len(ks)} | " + " | ".join(cells) + " |")

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
