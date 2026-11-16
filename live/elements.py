"""The security gateway (C1-C5) as AgentDojo pipeline elements.

Pipeline for a gateway configuration:

    SystemMessage -> InitQuery -> GatewayInit -> LLM ->
        ToolsExecutionLoop[ GatewayToolsExecutor -> LLM ] -> GatewayFinalAnswer

* GatewayInit         new SecurityGateway per episode; registers the user request
                      as trusted text (C2 ledger); adds the spotlighting note to
                      the system message when C2 is on.
* GatewayToolsExecutor  outbound path: every proposed tool call goes through
                      gateway.tool_call (C3 intent + provenance, C4 argument
                      checks, C5 log) BEFORE execution; CONFIRM is resolved by the
                      confirmation policy. Inbound path: every tool output goes
                      through gateway.tool_output (C1 quarantine, C2 ledger and
                      spotlighting, C5 log) BEFORE the LLM sees it.
* GatewayFinalAnswer  C4 on the final answer.
"""
from __future__ import annotations

import time
from ast import literal_eval

import yaml
from pydantic import BaseModel
from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (ChatMessage, ChatSystemMessage, ChatToolResultMessage,
                             get_text_content_as_str, text_content_block_from_string)

from gateway import Decision, GatewayConfig, PolicyEngine, SecurityGateway

from gateway.redact import to_plain

from . import confirm
from .contacts import trusted_identities
from .episode import current


def _render_plain(original, plain) -> str:
    """Format a (redacted) plain structure exactly as AgentDojo's tool_result_to_str
    formats the original result (YAML for models and lists, str otherwise)."""
    if isinstance(original, BaseModel):
        return yaml.safe_dump(plain).strip()
    if isinstance(original, list):
        items = [str(x) if type(x) in (str, int) else x for x in plain]
        return yaml.safe_dump(items).strip()
    return str(plain)


class GatewayInit(BasePipelineElement):
    def __init__(self, cfg: GatewayConfig, use_intent: bool = True, use_provenance: bool = True):
        self.cfg = cfg
        self.use_intent = use_intent
        self.use_provenance = use_provenance

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ep = current()
        gw = SecurityGateway(self.cfg, policy=PolicyEngine(use_intent=self.use_intent,
                                                           use_provenance=self.use_provenance))
        gw.user_request(query)
        if self.cfg.trusted_contacts:               # M1
            ep.trusted_ids = gw.register_trusted_identities(trusted_identities(env))
        ep.delegated = gw.policy.delegated          # M2
        ep.gateway = gw
        # ground truth of the user task, for the oracle confirmation policy
        ep.gt_calls = []
        if ep.user_task is not None:
            try:
                ep.gt_calls = list(ep.user_task.ground_truth(env.model_copy(deep=True)))
            except Exception:
                ep.gt_calls = []
        messages = list(messages)
        note = gw.system_prompt_addendum()
        if note and messages and messages[0]["role"] == "system":
            old = get_text_content_as_str(messages[0]["content"])
            messages[0] = ChatSystemMessage(role="system",
                                            content=[text_content_block_from_string(f"{old}\n\n{note}")])
        return query, runtime, env, messages, extra_args


class GatewayToolsExecutor(ToolsExecutor):
    def __init__(self, confirm_policy: str = "oracle", tool_output_formatter=tool_result_to_str):
        super().__init__(tool_output_formatter)
        self.confirm_policy = confirm_policy

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        ep = current()
        gw: SecurityGateway = ep.gateway
        known = {t.name for t in runtime.functions.values()}
        results = []
        for tc in messages[-1]["tool_calls"]:
            def _err(msg):
                return ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                             tool_call_id=tc.id, tool_call=tc, error=msg)
            if tc.function not in known:
                results.append(_err(f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            ep.tool_calls += 1

            # ---- outbound path: C3 + C4 (+ C5 log)
            t0 = time.perf_counter()
            decision = gw.tool_call(tc.function, dict(tc.args))
            ep.gateway_ms += (time.perf_counter() - t0) * 1000
            reasons = gw.logger.records[-1].get("reasons", []) if gw.logger.records else []
            approved = None
            if decision is Decision.CONFIRM:
                ep.confirms += 1
                approved = confirm.resolve(self.confirm_policy, tc.function, dict(tc.args), ep.gt_calls)
                ep.confirms_approved += int(approved)
            ep.decisions.append({"tool": tc.function, "decision": decision.value,
                                 "approved": approved, "reasons": reasons})
            if decision is Decision.DENY or (decision is Decision.CONFIRM and not approved):
                ep.denied += 1
                why = "; ".join(reasons) if reasons else decision.value
                results.append(_err(f"Blocked by security gateway ({decision.value}): {why}"))
                continue
            ep.allowed += 1

            # ---- execute
            res, error = runtime.run_function(env, tc.function, tc.args)
            text = self.output_formatter(res)

            # ---- inbound path: C1 (or M3) + C2 (+ C5 log)
            if error is None:
                t0 = time.perf_counter()
                if gw.cfg.redaction == "record":
                    text, action = gw.tool_result(tc.function, text, to_plain(res),
                                                  lambda plain, _r=res: _render_plain(_r, plain))
                else:
                    text, action = gw.tool_result(tc.function, text)
                ep.gateway_ms += (time.perf_counter() - t0) * 1000
                if action == "quarantine":
                    ep.quarantined += 1
                elif action == "redact":
                    ep.redacted += 1
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                 tool_call_id=tc.id, tool_call=tc, error=error))
        return query, runtime, env, [*messages, *results], extra_args


class GatewayFinalAnswer(BasePipelineElement):
    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ep = current()
        gw: SecurityGateway = ep.gateway
        if not messages or messages[-1]["role"] != "assistant" or messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        content = messages[-1]["content"]
        if not content:
            return query, runtime, env, messages, extra_args
        text = get_text_content_as_str(content)
        out = gw.final_answer(text)
        if out != text:
            ep.answer_withheld = True
            messages = list(messages)
            last = dict(messages[-1])
            last["content"] = [text_content_block_from_string(out)]
            messages[-1] = last
        return query, runtime, env, messages, extra_args
