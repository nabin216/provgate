"""Integration tests for the live pipeline (no API calls; scripted agent)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentdojo.attacks.attack_registry import ATTACKS  # noqa: E402
from agentdojo.functions_runtime import FunctionCall  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from live import pipelines  # noqa: E402
from live.confirm import oracle_approves  # noqa: E402
from live.episode import new_episode  # noqa: E402
from live.scoring import install  # noqa: E402
from live.scripted import ScriptedWCCA  # noqa: E402

install()
SUITES = get_suites("v1.2")


def run(config, suite_name, ut_id, it_id=None, attack="important_instructions"):
    suite = SUITES[suite_name]
    pipe = pipelines.build(config, ScriptedWCCA())
    ut = suite.user_tasks[ut_id]
    it = suite.injection_tasks[it_id] if it_id else None
    inj = ATTACKS[attack](suite, pipe).attack(ut, it) if it else {}
    ep = new_episode(user_task=ut, injection_task=it, injections=inj)
    utility, security = suite.run_task_with_pipeline(pipe, ut, it, inj)
    return utility, security, ep


def test_benign_task_unaffected_by_full_gateway():
    u, _, ep = run("G4", "banking", "user_task_0")
    assert u and ep.denied == 0


def test_attack_succeeds_without_defence():
    _, s, _ = run("B0", "banking", "user_task_0", "injection_task_0")
    assert s, "scripted worst-case agent should be hijacked with no defence"


def test_provenance_stops_attacker_iban():
    # user asks to pay a bill; injection asks to send money to the attacker's IBAN
    _, s, ep = run("G3-deny", "banking", "user_task_0", "injection_task_0")
    assert not s
    assert any(d["decision"] == "confirm" and d["tool"] == "send_money" for d in ep.decisions)


def test_detection_quarantines_templated_injection():
    _, s, ep = run("G1", "banking", "user_task_0", "injection_task_0")
    assert ep.quarantined >= 1 and not s


def test_oracle_only_approves_user_requested_destination():
    gt = [FunctionCall(function="send_money", args={"recipient": "UK12345678901234567890", "amount": 98.7})]
    assert oracle_approves("send_money", {"recipient": "uk12345678901234567890", "amount": 1}, gt)
    assert not oracle_approves("send_money", {"recipient": "US133000000121212121212"}, gt)
    assert not oracle_approves("send_email", {"recipients": ["a@b.c"]}, gt)


def test_spotlight_note_added_only_with_c2():
    from live.episode import current
    for cfg, expect in [("G4", True), ("G4-noC2", False)]:
        suite = SUITES["banking"]
        pipe = pipelines.build(cfg, ScriptedWCCA())
        ut = suite.user_tasks["user_task_0"]
        new_episode(user_task=ut)
        from agentdojo.functions_runtime import FunctionsRuntime
        env = suite.load_and_inject_default_environment({})
        _, _, _, msgs, _ = pipe.query(ut.PROMPT, FunctionsRuntime(suite.tools), env)
        sys_text = msgs[0]["content"][0]["content"]
        assert ("untrusted sources" in sys_text) is expect
        assert current().gateway is not None


@pytest.mark.parametrize("cfg", ["B0", "B3", "B4", "G1", "G2", "G3", "G4", "G4-noC2", "G4-deny"])
def test_every_config_builds_and_runs(cfg):
    u, _, _ = run(cfg, "slack", "user_task_1")
    assert isinstance(u, bool)
