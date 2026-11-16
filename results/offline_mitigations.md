# RQ3 offline: mitigations M1-M3 (scripted worst-case agent)

Attack styles: direct, ignore_previous, important_instructions_no_names, injecagent, system_message, tool_knowledge. Attack pairs where the undefended attack succeeded: 3498.
Benign: 97 user tasks. 'Interrupted' = at least one deny, unapproved confirm, or withheld/redacted output.

| Config | WCCA ASR | Benign utility | Benign tasks with a confirm | Confirms per benign task | Attacked: outputs withheld | Attacked: outputs redacted |
|---|---|---|---|---|---|---|
| G1 | 28.2% [26.7-29.7] (n=3498) | 100.0% [96.2-100.0] | 0 | 0.00 | 5878 | 0 |
| G1-M3 | 28.2% [26.7-29.7] (n=3498) | 100.0% [96.2-100.0] | 0 | 0.00 | 449 | 5429 |
| G3 | 4.5% [3.8-5.2] (n=3498) | 94.8% [88.5-97.8] | 21 | 0.35 | 0 | 0 |
| G3-M1 | 4.5% [3.8-5.2] (n=3498) | 94.8% [88.5-97.8] | 16 | 0.25 | 0 | 0 |
| G3-M2 | 4.6% [4.0-5.4] (n=3498) | 100.0% [96.2-100.0] | 25 | 0.42 | 0 | 0 |
| G3+ | 4.6% [4.0-5.4] (n=3498) | 100.0% [96.2-100.0] | 20 | 0.32 | 0 | 0 |
| G3-deny | 3.9% [3.3-4.6] (n=3498) | 76.3% [66.9-83.6] | 21 | 0.35 | 0 | 0 |
| G3+-deny | 3.9% [3.3-4.6] (n=3498) | 81.4% [72.6-87.9] | 20 | 0.32 | 0 | 0 |
| G4 | 1.4% [1.1-1.9] (n=3498) | 94.8% [88.5-97.8] | 21 | 0.35 | 5878 | 0 |
| G4-M3 | 1.4% [1.1-1.9] (n=3498) | 94.8% [88.5-97.8] | 21 | 0.35 | 449 | 5429 |
| G4+ | 1.5% [1.1-1.9] (n=3498) | 100.0% [96.2-100.0] | 20 | 0.32 | 449 | 5429 |
| G4-deny | 1.3% [0.9-1.7] (n=3498) | 76.3% [66.9-83.6] | 21 | 0.35 | 5698 | 0 |
| G4+-deny | 1.3% [0.9-1.7] (n=3498) | 81.4% [72.6-87.9] | 20 | 0.32 | 449 | 5249 |
| G5 | 1.5% [1.1-1.9] (n=3498) | 100.0% [96.2-100.0] | 20 | 0.32 | 449 | 5429 |

## Paired changes (mitigated vs base)

Security: attacks that succeed only in one configuration (B0-successful pairs). Utility: benign tasks completed only in one configuration.

| Base -> mitigated | attacks: only base / only mitigated | p | benign: only base / only mitigated | p |
|---|---|---|---|---|
| G3 -> G3-M1 | 0 / 0 | 1 | 0 / 0 | 1 |
| G3 -> G3-M2 | 0 / 6 | 0.031 | 0 / 5 | 0.062 |
| G3 -> G3+ | 0 / 6 | 0.031 | 0 / 5 | 0.062 |
| G3-deny -> G3+-deny | 0 / 0 | 1 | 0 / 5 | 0.062 |
| G1 -> G1-M3 | 0 / 0 | 1 | 0 / 0 | 1 |
| G4 -> G4-M3 | 0 / 0 | 1 | 0 / 0 | 1 |
| G4 -> G4+ | 0 / 2 | 0.5 | 0 / 5 | 0.062 |
| G4-deny -> G4+-deny | 0 / 0 | 1 | 0 / 5 | 0.062 |
| G4+ -> G5 | 0 / 0 | 1 | 0 / 0 | 1 |

## WCCA ASR by attack style (%, over B0-successful pairs)

| Attack | n | G1 | G1-M3 | G3 | G3-M1 | G3-M2 | G3+ | G3-deny | G3+-deny | G4 | G4-M3 | G4+ | G4-deny | G4+-deny | G5 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| direct | 583 | 91.4 | 91.4 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 4.5 | 4.5 | 4.6 | 3.9 | 3.9 | 4.6 |
| ignore_previous | 583 | 77.5 | 77.5 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 4.1 | 4.1 | 4.3 | 3.6 | 3.6 | 4.3 |
| important_instructions_no_names | 583 | 0.0 | 0.0 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| injecagent | 583 | 0.0 | 0.0 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| system_message | 583 | 0.0 | 0.0 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| tool_knowledge | 583 | 0.0 | 0.0 | 4.5 | 4.5 | 4.6 | 4.6 | 3.9 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

## WCCA ASR by suite (%, all attack styles)

| Suite | n | G1 | G1-M3 | G3 | G3-M1 | G3-M2 | G3+ | G3-deny | G3+-deny | G4 | G4-M3 | G4+ | G4-deny | G4+-deny | G5 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| banking | 864 | 30.8 | 30.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| slack | 630 | 33.3 | 33.3 | 3.8 | 3.8 | 4.8 | 4.8 | 1.0 | 1.0 | 1.3 | 1.3 | 1.6 | 0.3 | 0.3 | 1.6 |
| travel | 696 | 30.5 | 30.5 | 17.2 | 17.2 | 17.2 | 17.2 | 17.2 | 17.2 | 5.7 | 5.7 | 5.7 | 5.7 | 5.7 | 5.7 |
| workspace | 1308 | 22.7 | 22.7 | 0.9 | 0.9 | 0.9 | 0.9 | 0.9 | 0.9 | 0.2 | 0.2 | 0.2 | 0.2 | 0.2 | 0.2 |
