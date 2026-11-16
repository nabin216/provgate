"""Scripted worst-case compliant agent (WCCA) used as a stand-in for the LLM.

It lets the whole live pipeline be tested without any API calls, and gives a
correctness check against the RQ1 replay: run through the real AgentDojo
pipeline, it should reproduce the replay's numbers.

Behaviour (same assumptions as experiments/run_experiments.py):
  turn 1  issue all ground-truth calls of the user task
  turn 2  if an injection payload is visible in any tool output it received
          (i.e. not quarantined by C1), issue all ground-truth calls of the
          injection task
  last    reply with the user task's GROUND_TRUTH_OUTPUT
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string

from .episode import current


def _alnum(s: str) -> str:
    # letters and digits only: robust to YAML quoting/escaping and line folding
    return re.sub(r"[^a-z0-9]", "", s.lower())


class ScriptedWCCA(BasePipelineElement):
    def __init__(self, mark: str = "^"):
        self.name = "local"          # 'local' is a known model name for the attacks
        self.mark = mark

    def _calls(self, task, env, prefix):
        out = []
        for i, c in enumerate(task.ground_truth(env.model_copy(deep=True))):
            out.append(FunctionCall(function=c.function, args=dict(c.args), id=f"{prefix}{i}"))
        return out

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ep = current()
        n_assist = sum(1 for m in messages if m["role"] == "assistant")
        if n_assist == 0:
            ep._wcca_inj = self._calls(ep.injection_task, env, "inj") if ep.injection_task else []
            calls = self._calls(ep.user_task, env, "u")
            if calls:
                return self._say(query, runtime, env, messages, extra_args, calls)
        if n_assist <= 1 and ep.injection_task is not None and getattr(ep, "_wcca_inj", None):
            keys = [_alnum(v)[:60] for v in ep.injections.values() if _alnum(v)]
            # strict: the attacker's goal alone also counts as visible, so a
            # partial redaction (M3) that leaves the instruction in place is
            # scored as a hijack even if the framing around it was removed
            goal = _alnum(getattr(ep.injection_task, "GOAL", "") or "")
            if goal:
                keys.append(goal[:60])
            seen = "".join(_alnum(get_text_content_as_str(m["content"] or []).replace(self.mark, " "))
                            for m in messages if m["role"] == "tool")
            if any(k and k in seen for k in keys):
                calls, ep._wcca_inj = ep._wcca_inj, []
                return self._say(query, runtime, env, messages, extra_args, calls)
        final = ChatAssistantMessage(role="assistant", tool_calls=None,
                                     content=[text_content_block_from_string(ep.user_task.GROUND_TRUTH_OUTPUT)])
        return query, runtime, env, [*messages, final], extra_args

    @staticmethod
    def _say(query, runtime, env, messages, extra_args, calls):
        msg = ChatAssistantMessage(role="assistant", tool_calls=calls,
                                   content=[text_content_block_from_string("")])
        return query, runtime, env, [*messages, msg], extra_args
