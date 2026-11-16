"""Confirmation policies for automated runs (no human present).

When the gateway returns CONFIRM, a fixed policy stands in for the user:

* deny   - every confirmation is rejected (lower bound on utility).
* oracle - a confirmation is approved if and only if the proposed call matches
           a ground-truth call of the *user* task: same tool, and every value of
           every sensitive (destination) argument of the proposed call also
           appears in that argument of a ground-truth call. Tools without
           sensitive arguments match on the tool name. This models an attentive
           user who approves what they asked for and nothing else
           (upper bound on utility).
"""
from __future__ import annotations

from gateway.policy import CATALOGUE, EGRESS_READ_TOOLS, _norm


def _sensitive_args(tool: str) -> tuple[str, ...]:
    spec = CATALOGUE.get(tool)
    if spec is not None:
        return spec.sensitive_args
    return EGRESS_READ_TOOLS.get(tool, ())


def oracle_approves(tool: str, args: dict, gt_calls) -> bool:
    sens = _sensitive_args(tool)
    for c in gt_calls:
        if c.function != tool:
            continue
        ok = True
        for a in sens:
            want = set(_norm(c.args.get(a)))
            got = _norm(args.get(a))
            if any(v not in want for v in got):
                ok = False
                break
        if ok:
            return True
    return False


def resolve(policy: str, tool: str, args: dict, gt_calls) -> bool:
    if policy == "deny":
        return False
    if policy == "oracle":
        return oracle_approves(tool, args, gt_calls)
    raise ValueError(f"unknown confirmation policy {policy!r}")
