"""Run live AgentDojo episodes for one model and one or more configurations.

Examples
  # smoke test: 1 benign + 1 attacked episode, no defence and full gateway
  python run_live.py --configs B0 G4 --suites workspace --user-tasks user_task_0 \
      --injection-tasks injection_task_0 --benign --attack important_instructions

  # pilot: all 97 benign tasks, B0
  python run_live.py --configs B0 --benign --no-attack

  # offline check, no API calls (scripted worst-case agent)
  python run_live.py --model scripted --configs B0 G1 G3 G4-deny --attack important_instructions_no_names

Results: runs/<model>/<config>/<attack or benign>/rep<k>.jsonl (one line per
episode). Re-running the same command skips episodes already done, so a crashed
or rate-limited run can simply be restarted.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from agentdojo.attacks.attack_registry import ATTACKS  # noqa: E402
from agentdojo.models import MODEL_NAMES  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from live import pipelines  # noqa: E402
from live.episode import new_episode  # noqa: E402
from live.scoring import install as _install_scoring  # noqa: E402

_install_scoring()

_write_lock = threading.Lock()


def load_env_file(path: Path):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def make_llm(cfg: dict):
    if cfg["model"] == "scripted":
        from live.scripted import ScriptedWCCA
        return ScriptedWCCA()
    from live.llm import ChatLLM, make_client
    client = make_client(cfg["provider"], cfg.get("base_url"))
    return ChatLLM(client, cfg["model"], temperature=cfg.get("temperature", 0.0),
                   reasoning_effort=cfg.get("reasoning_effort"))


def slug(s: str) -> str:
    return s.replace("/", "_").replace(":", "_")


def done_keys(path: Path) -> set:
    keys = set()
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                r = json.loads(line)
                keys.add((r["suite"], r["user_task"], r["injection_task"]))
            except Exception:
                pass
    return keys


def run_episode(suite, pipeline, ut, it, injections, cfg_name):
    ep = new_episode(user_task=ut, injection_task=it, injections=injections)
    t0 = time.perf_counter()
    utility, security = suite.run_task_with_pipeline(pipeline, ut, it, injections)
    wall = time.perf_counter() - t0
    gw_log = ep.gateway.logger.records if ep.gateway is not None else []
    return {
        "utility": bool(utility), "security": bool(security),   # security=True means the ATTACK succeeded
        "wall_s": round(wall, 3), "gateway_ms": round(ep.gateway_ms, 3),
        "llm_calls": ep.llm_calls, "prompt_tokens": ep.prompt_tokens,
        "completion_tokens": ep.completion_tokens, "llm_errors": ep.llm_errors,
        "tool_calls": ep.tool_calls, "allowed": ep.allowed, "blocked": ep.denied,
        "confirms": ep.confirms, "confirms_approved": ep.confirms_approved,
        "quarantined": ep.quarantined, "redacted": ep.redacted, "answer_withheld": ep.answer_withheld,
        "trusted_ids": ep.trusted_ids, "delegated": ep.delegated,
        "decisions": ep.decisions,
    }, gw_log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-file", default=str(ROOT / "config.yaml"))
    ap.add_argument("--model", help="override model in config.yaml ('scripted' = offline WCCA agent)")
    ap.add_argument("--configs", nargs="+", default=["B0"], help=f"any of {pipelines.ALL_CONFIGS}")
    ap.add_argument("--suites", nargs="+", default=None)
    ap.add_argument("--user-tasks", nargs="+", default=None)
    ap.add_argument("--injection-tasks", nargs="+", default=None)
    ap.add_argument("--attack", default=None, help="attack name (default from config.yaml)")
    ap.add_argument("--no-attack", action="store_true", help="skip attacked episodes")
    ap.add_argument("--benign", action="store_true", help="also run benign (no-injection) episodes")
    ap.add_argument("--rep", type=int, default=0, help="repetition index")
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--limit", type=int, default=None, help="max episodes per config (for pilots)")
    ap.add_argument("--out", default=str(ROOT / "runs"))
    args = ap.parse_args()

    load_env_file(ROOT / ".env")
    cfg = yaml.safe_load(Path(args.config_file).read_text())
    if args.model:
        cfg["model"] = args.model
    if cfg["model"] == "scripted":
        cfg["provider"] = "none"
    attack_name = args.attack or cfg.get("attack", "important_instructions")
    workers = args.workers or cfg.get("workers", 1)
    MODEL_NAMES.setdefault(cfg["model"], cfg.get("attack_model_name", "AI assistant"))

    llm = make_llm(cfg)
    suites = get_suites(cfg.get("benchmark_version", "v1.2"))
    if attack_name.startswith("rq4"):           # RQ4 adaptive attacks + new injection tasks
        from live import rq4
        rq4.install(suites)
    suite_names = args.suites or list(suites)

    for cname in args.configs:
        pipeline = pipelines.build(cname, llm)
        jobs = []
        modes = (["benign"] if args.benign else []) + ([] if args.no_attack else [attack_name])
        for mode in modes:
            out = Path(args.out) / slug(cfg["model"]) / cname / mode / f"rep{args.rep}.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True)
            logf = out.with_name(f"rep{args.rep}.gateway.jsonl")
            errf = out.with_name(f"rep{args.rep}.errors.jsonl")
            done = done_keys(out)
            for sname in suite_names:
                suite = suites[sname]
                attack = ATTACKS[attack_name](suite, pipeline) if mode != "benign" else None
                uts = [suite.user_tasks[u] for u in (args.user_tasks or suite.user_tasks) if u in suite.user_tasks]
                for ut in uts:
                    if mode == "benign":
                        pairs = [(None, {})]
                    else:
                        pairs = []
                        for iid in (args.injection_tasks or suite.injection_tasks):
                            if iid not in suite.injection_tasks:
                                continue
                            it = suite.injection_tasks[iid]
                            try:
                                inj = attack.attack(ut, it)
                            except Exception:
                                inj = {}
                            if inj:
                                pairs.append((it, inj))
                    for it, inj in pairs:
                        key = (sname, ut.ID, it.ID if it else None)
                        if key not in done:
                            jobs.append((suite, sname, ut, it, inj, mode, out, logf, errf))
        if args.limit:
            jobs = jobs[: args.limit]
        print(f"[{cname}] {len(jobs)} episodes to run (model={cfg['model']}, attack={attack_name}, "
              f"workers={workers})", flush=True)

        def work(job):
            suite, sname, ut, it, inj, mode, out, logf, errf = job
            base = {"model": cfg["model"], "config": cname, "mode": mode, "attack": None if mode == "benign" else attack_name,
                    "suite": sname, "user_task": ut.ID, "injection_task": it.ID if it else None, "rep": args.rep}
            try:
                res, gw_log = run_episode(suite, pipeline, ut, it, inj, cname)
            except Exception as e:
                with _write_lock, errf.open("a") as f:
                    f.write(json.dumps({**base, "error": f"{type(e).__name__}: {e}",
                                        "trace": traceback.format_exc()[-2000:]}) + "\n")
                return base, None
            with _write_lock:
                with out.open("a") as f:
                    f.write(json.dumps({**base, **res}, default=str) + "\n")
                if gw_log:
                    with logf.open("a") as f:
                        for r in gw_log:
                            f.write(json.dumps({"episode": [sname, ut.ID, base["injection_task"]], **r},
                                               default=str) + "\n")
            return base, res

        n = ok = att = util = errs = 0
        t_start = time.time()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(work, j) for j in jobs]
            for fu in as_completed(futs):
                base, res = fu.result()
                n += 1
                if res is None:
                    errs += 1
                else:
                    ok += 1
                    util += res["utility"]
                    att += res["security"] if base["mode"] != "benign" else 0
                if n % 10 == 0 or n == len(jobs):
                    rate = n / max(time.time() - t_start, 1e-6) * 3600
                    print(f"  [{cname}] {n}/{len(jobs)} done | utility {util}/{ok} | attack success {att} "
                          f"| errors {errs} | {rate:.0f} episodes/h", flush=True)
        if n:
            print(f"[{cname}] finished: utility {util}/{ok}, attack success {att}, errors {errs}", flush=True)


if __name__ == "__main__":
    main()
