# Offline validation: live pipeline vs RQ1 replay

Scripted worst-case agent through the real AgentDojo pipeline (no LLM).
Live ASR is over pairs where the undefended attack succeeded (B0).

Attack pairs run: 5694; succeeded with no defence: 3365

| Config | Live ASR (all 6 attacks) | Replay ASR | Live benign utility | Replay benign uninterrupted |
|---|---|---|---|---|
| G1 |  29.3% [27.8-30.8] (n=3365) | 34.8% | 100.0% [96.2-100.0] | 95.9% |
| G2 |  37.6% [35.9-39.2] (n=3365) | 37.6% |  94.8% [88.5-97.8] | 94.8% |
| G3-deny |   3.5% [2.9-4.2] (n=3365) | 4.8% |  76.3% [66.9-83.6] | 74.2% |
| G4-deny |   1.3% [1.0-1.8] (n=3365) | 2.2% |  76.3% [66.9-83.6] | 70.1% |

## By attack style (live ASR over B0-successful pairs)

| Attack | n | G1 | G2 | G3-deny | G4-deny |
|---|---|---|---|---|---|
| direct | 583 | 91.4 | 37.0 | 3.9 | 3.9 |
| ignore_previous | 583 | 77.5 | 37.0 | 3.9 | 3.6 |
| important_instructions_no_names | 450 | 0.0 | 40.9 | 0.7 | 0.0 |
| injecagent | 583 | 0.0 | 37.0 | 3.9 | 0.0 |
| system_message | 583 | 0.0 | 37.0 | 3.9 | 0.0 |
| tool_knowledge | 583 | 0.0 | 37.0 | 3.9 | 0.0 |
