# ProvGate

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24289759.svg)](https://doi.org/10.5281/zenodo.24289759)

**A layered runtime security gateway against prompt injection and unauthorized tool use in LLM agents.**

This repository contains the code, policies and analysis scripts for the paper

> A. Z. Nabin, "Mediate, Don't Just Detect: Design and Experimental Evaluation of a Layered Runtime Security Gateway Against Prompt Injection and Unauthorized Tool Use in LLM Agents," manuscript under review, 2026.

The gateway sits between an LLM agent and its tools. Every tool output that enters the agent's context, and every tool call that leaves it, passes through five controls:

| Control | What it does |
|---|---|
| **C1** Injection detection | Scores tool outputs; with **M3** it redacts only the flagged record instead of the whole output |
| **C2** Provenance ledger | Records which text is trusted (the user's request) and which is untrusted (tool outputs); optional spotlighting |
| **C3** Tool authorisation | **C3a** task-scoped allow-list of write tools; **C3b** argument provenance: destinations (recipients, IBANs, URLs) must come from trusted text, otherwise the call needs confirmation |
| **C4** Output validation | Blocks exfiltration patterns (secrets, data in URLs, image beacons) in tool arguments and answers |
| **C5** Audit logging | One JSON line per decision |

Mitigations: **M1** trusted-contacts registry, **M2** delegated-task mode, **M3** record-level redaction. The recommended configuration is **G5** (C1 with M3, ledger without spotlighting, C3, C4 with a requested-secret exemption, M1, M2). The gateway needs no extra LLM calls and adds about 2 ms per tool call.

## Results in brief (AgentDojo v1.2, *important instructions* attack)

| Model | No defence: attack success | G5: attack success | G5: utility under attack (no defence) |
|---|---|---|---|
| GPT-OSS-20B | 30.1% | 0.0% | 59.1% (41.5%) |
| Qwen3.8-27B | 3.9% | 0.0% | 77.2% (81.9%) |
| Gemini 3.8 Flash | 0.0% | 0.0% | 89.6% (95.4%) |

See the paper for all configurations, baselines, adaptive attacks and statistics.

## Layout

```
gateway/        C1–C5 and M3 (redact.py): the gateway itself, framework-independent
live/           the gateway as AgentDojo pipeline elements, model client, M1 contacts,
                scripted worst-case agent, adaptive attacks (rq4.py)
tests/          41 unit and integration tests (no API calls)
run_live.py     run episodes → runs/<model>/<config>/<attack|benign>/rep<k>.jsonl (resumable)
summarise_live.py, breakdown.py, cost_table.py, rq4_table.py, validate_*.py   analysis
config*.yaml    frozen run settings per model provider
results/        offline (RQ1, RQ3, RQ4) summaries
docs/LAB.md     detailed description of the pipeline, configurations and corrections
```

## Quick start

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q tests                 # 41 tests, no API key needed
```

Offline (no API calls, scripted worst-case agent):

```bash
python run_live.py --model scripted --configs B0 G3 G5 --benign --attack important_instructions --out runs_offline
python validate_mitigations.py --runs runs_offline
```

Live (needs an API key in `.env`, e.g. `GROQ_API_KEY=...`; never commit it):

```bash
python run_live.py --configs B0 G3 G5 --benign --attack important_instructions
python summarise_live.py --configs B0 G3 G5
```

Other providers: `--config-file config_gemini.yaml` (Gemini API, `GEMINI_API_KEY`) or `config_vertex.yaml` (Vertex AI, service-account key in `gcp-key.json`; replace `YOUR_PROJECT_ID`).

## Notes for replication

- Temperature 0 is sent explicitly; AgentDojo 0.1.35 otherwise drops it.
- Attacks are scored on tool calls that actually executed (`live/scoring.py`).
- Gemini 3 needs each tool call's *thought signature* echoed back; `live/llm.py` stores and re-attaches it.
- The benchmark's attack payloads contain simulated fraud and phishing instructions. Some hosted providers' abuse detection may flag high-volume runs; one of our cloud projects was suspended for this reason.

## Data

Raw episode logs and gateway decision logs for all live runs: [doi:10.5281/zenodo.24290215](https://doi.org/10.5281/zenodo.24290215) (5.4 MB, CC-BY-4.0).

## Citation

See `CITATION.cff`. Archived version: [doi:10.5281/zenodo.24289759](https://doi.org/10.5281/zenodo.24289759) (v1.0.0, as used in the paper).

## Licence

MIT, see `LICENSE`.
