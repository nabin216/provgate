"""Per-episode state shared by the pipeline elements and the runner.

AgentDojo pipeline elements are created once and reused for every episode, so
anything that belongs to a single episode (the gateway instance with its
provenance ledger, the user task for the oracle, counters) lives here. It is
thread-local so several episodes can run in parallel threads.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

_local = threading.local()


@dataclass
class Episode:
    user_task: Any = None
    injection_task: Any = None
    injections: dict = field(default_factory=dict)
    gateway: Any = None               # gateway.SecurityGateway for G* configs
    gt_calls: list = field(default_factory=list)   # user-task ground truth (oracle)
    # counters
    tool_calls: int = 0
    allowed: int = 0
    denied: int = 0
    confirms: int = 0
    confirms_approved: int = 0
    quarantined: int = 0
    redacted: int = 0                 # M3: outputs with records redacted
    trusted_ids: int = 0              # M1: registry size
    delegated: bool = False           # M2: delegation mode switched on
    answer_withheld: bool = False
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    llm_errors: int = 0
    gateway_ms: float = 0.0
    decisions: list = field(default_factory=list)


def new_episode(**kw) -> Episode:
    ep = Episode(**kw)
    _local.ep = ep
    return ep


def current() -> Episode:
    ep = getattr(_local, "ep", None)
    if ep is None:
        ep = new_episode()
    return ep
