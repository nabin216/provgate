"""LLM element for any OpenAI-compatible endpoint (Groq, vLLM, Ollama, OpenAI).

Differences from AgentDojo 0.1.35's OpenAILLM (report these in the paper):
* temperature is always sent. AgentDojo sends `temperature or NOT_GIVEN`, which
  silently drops temperature=0 so the provider default (usually 1.0) is used.
* token usage is counted per episode.
* a provider-side "invalid tool call" error (e.g. Groq's `tool_use_failed`) is
  retried, then ends the episode with an empty answer instead of crashing the run.
"""
from __future__ import annotations

import os
import time
from collections.abc import Sequence

import openai
from agentdojo.agent_pipeline.llms.openai_llm import (OpenAILLM, _function_to_openai, _message_to_openai,
                                                     _openai_to_assistant_message)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, text_content_block_from_string

from .episode import current

PROVIDERS = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "openai": (None, "OPENAI_API_KEY"),
    "vertex": (None, None),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY"),
    "vllm": ("http://localhost:8000/v1", None),
    "ollama": ("http://localhost:11434/v1", None),
}


def make_client(provider: str, base_url: str | None = None) -> openai.OpenAI:
    default_url, key_env = PROVIDERS[provider]
    key = os.environ.get(key_env, "") if key_env else "EMPTY"
    if key_env and not key:
        raise SystemExit(f"{key_env} is not set (put it in .env)")
    client = openai.OpenAI(api_key=key, base_url=base_url or default_url, timeout=120.0, max_retries=8)
    if provider == "vertex":
        client._vertex = _VertexToken(
            os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "gcp-key.json"))
        client.api_key = client._vertex.get()
    return client


class ChatLLM(OpenAILLM):
    def __init__(self, client, model: str, temperature: float = 0.0,
                 reasoning_effort: str | None = None, max_tool_errors: int = 2):
        super().__init__(client, model, reasoning_effort=reasoning_effort, temperature=temperature)
        self.name = model
        self.max_tool_errors = max_tool_errors

    def _create(self, msgs, tools):
        kw = dict(model=self.model, messages=msgs)
        # GPT-5 / o-series reasoning models reject a temperature other than the
        # default; config_gpt5.yaml sets temperature: null so it is not sent.
        if self.temperature is not None:
            kw["temperature"] = self.temperature
        if tools:
            kw.update(tools=tools, tool_choice="auto")
        if self.reasoning_effort:
            kw["reasoning_effort"] = self.reasoning_effort
        tok = getattr(self.client, "_vertex", None)
        if tok is not None:
            self.client.api_key = tok.get()
        return self.client.chat.completions.create(**kw)

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ep = current()
        msgs = [_message_to_openai(m, self.model) for m in messages]
        # AgentDojo sends the system prompt with role 'developer' (OpenAI style).
        # Non-OpenAI models (e.g. Qwen) reject that role, so send it as 'system'.
        # OpenAI-family models (gpt-oss, gpt-*, o*) keep 'developer', unchanged.
        if not self.model.startswith(("openai/", "gpt-", "o1", "o3", "o4")):
            for m in msgs:
                if m.get("role") == "developer":
                    m["role"] = "system"
                    c = m.get("content")
                    if isinstance(c, list):
                        m["content"] = "".join(x.get("text", "") for x in c)
        _restore_sigs(msgs, ep, self.model)
        tools = [_function_to_openai(t) for t in runtime.functions.values()]
        completion = None
        for attempt in range(self.max_tool_errors + 1):
            try:
                completion = self._create(msgs, tools)
                break
            except openai.BadRequestError as e:
                body = str(e)
                if "tool_use_failed" in body or "tool call validation" in body.lower() or "parse" in body.lower():
                    ep.llm_errors += 1
                    time.sleep(1)
                    continue
                raise
        ep.llm_calls += 1
        if completion is None:
            out = ChatAssistantMessage(role="assistant", tool_calls=None,
                                       content=[text_content_block_from_string("")])
            return query, runtime, env, [*messages, out], extra_args
        if completion.usage is not None:
            ep.prompt_tokens += completion.usage.prompt_tokens or 0
            ep.completion_tokens += completion.usage.completion_tokens or 0
        _save_sigs(completion, ep)
        try:
            out = _openai_to_assistant_message(completion.choices[0].message)
        except ValueError:  # malformed JSON arguments
            ep.llm_errors += 1
            out = ChatAssistantMessage(role="assistant", tool_calls=None,
                                       content=[text_content_block_from_string("")])
        return query, runtime, env, [*messages, out], extra_args


class _VertexToken:
    def __init__(self, keyfile):
        import threading
        from google.oauth2 import service_account
        sc = ["https://www.googleapis.com/auth/cloud-platform"]
        f = service_account.Credentials.from_service_account_file
        self.creds = f(keyfile, scopes=sc)
        self.lock = threading.Lock()

    def get(self):
        from google.auth.transport.requests import Request
        with self.lock:
            if not self.creds.valid:
                self.creds.refresh(Request())
            return self.creds.token


_DUMMY_SIG = {"google": {"thought_signature":
                         "skip_thought_signature_validator"}}


def _restore_sigs(msgs, ep, model):
    """Gemini 3 needs each tool call's thought signature sent back.
    AgentDojo's message format drops it, so it is kept per episode
    (by tool-call id) and re-attached. If none is known for a turn,
    Google's documented placeholder goes on the first call."""
    if not model.startswith(("google/", "gemini")):
        return
    sigs = getattr(ep, "sigs", {})
    for m in msgs:
        calls = m.get("tool_calls") or []
        found = False
        for t in calls:
            ec = sigs.get(t.get("id"))
            if ec:
                t["extra_content"] = ec
                found = True
        if calls and not found:
            calls[0]["extra_content"] = _DUMMY_SIG


def _save_sigs(completion, ep):
    if not hasattr(ep, "sigs"):
        ep.sigs = {}
    try:
        raw = completion.choices[0].message.model_dump()
    except Exception:
        return
    for t in raw.get("tool_calls") or []:
        ec = t.get("extra_content")
        if ec:
            ep.sigs[t["id"]] = ec
