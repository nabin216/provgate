"""Runtime security gateway: composes C1-C5 around an agent loop.

The gateway sits between the agent and (a) every piece of content entering the
model context and (b) every tool call leaving it (complete mediation).
Each control can be switched on/off to support the ablation experiments.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .context import ContextLedger, Segment, Spotlighter, Trust
from .detector import RuleDetector
from .output_validator import OutputValidator
from .policy import DELEGATION_RE, Decision, PolicyEngine, normalise_identity
from .redact import redact_obj


@dataclass
class GatewayConfig:
    detection: bool = True        # C1
    spotlight: bool = True        # C2
    authorisation: bool = True    # C3
    output_validation: bool = True  # C4
    logging: bool = True          # C5
    # RQ3 mitigations (all off by default, so G1-G4 are unchanged)
    trusted_contacts: bool = False  # M1: identities the user vouches for count as trusted
    delegation_mode: bool = False   # M2: delegated tasks turn C3a DENY into CONFIRM
    redaction: str = "output"       # M3: "output" = withhold whole output (C1); "record" = redact flagged records
    name: str = "full"


class SecurityLogger:
    """C5 - structured JSON-lines audit log."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []

    def log(self, **record):
        record["ts"] = time.time()
        self.records.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")


class SecurityGateway:
    def __init__(self, config: GatewayConfig | None = None, detector=None,
                 policy: PolicyEngine | None = None, validator: OutputValidator | None = None,
                 log_path=None):
        self.cfg = config or GatewayConfig()
        self.detector = detector or RuleDetector()
        self.policy = policy or PolicyEngine()
        self.validator = validator or OutputValidator()
        self.spot = Spotlighter()
        self.ledger = ContextLedger()
        self.logger = SecurityLogger(log_path)

    # ------------------------------------------------------------------ inputs
    def user_request(self, text: str) -> str:
        self.ledger.add(Segment(text, Trust.TRUSTED, "user"))
        if self.cfg.delegation_mode and DELEGATION_RE.search(text):
            self.policy.delegated = True
            if self.cfg.logging:
                self.logger.log(event="delegation_mode", on=True)
        return text

    def register_trusted_identities(self, values) -> int:
        """M1: identities the user vouches for (own address, organisation directory,
        people the user has written to, team workspace members). Only used when
        trusted_contacts is on. Returns the registry size."""
        if not self.cfg.trusted_contacts:
            return 0
        self.policy.trusted_ids |= {normalise_identity(v) for v in values if v}
        self.policy.trusted_ids.discard("")
        return len(self.policy.trusted_ids)

    def tool_result(self, tool: str, text: str, plain=None, render=None) -> tuple[str, str]:
        """Inbound path for a tool result. `text` is the formatted output; `plain`
        the structured result and `render(plain) -> text` its formatter, used by
        M3 (record-level redaction). Returns (text for the model, action)."""
        if not (self.cfg.detection and self.cfg.redaction == "record" and plain is not None and render):
            out = self.tool_output(tool, text)
            return out, (self.logger.records[-1].get("action", "pass") if self.logger.records else "pass")
        t0 = time.perf_counter()
        thr = self.detector.threshold
        action, flags = "pass", []
        score = self.detector.score(text)
        if score >= thr:
            flags.append(f"injection_score={score:.2f}")
            redacted, n = redact_obj(plain, self.detector)
            new = render(redacted) if n else text
            if n and self.detector.score(new) < thr:
                action, text = "redact", new
                flags.append(f"records_redacted={n}")
            else:   # safety net: original C1 behaviour
                action = "quarantine"
                text = f"[Content from {tool} withheld by security gateway: possible prompt injection]"
        seg = Segment(text, Trust.UNTRUSTED, f"tool:{tool}", flags)
        self.ledger.add(seg)
        out = self.spot.wrap(seg) if self.cfg.spotlight else seg.text
        if self.cfg.logging:
            self.logger.log(event="tool_output", tool=tool, action=action, flags=flags,
                            latency_ms=(time.perf_counter() - t0) * 1000)
        return out, action

    def tool_output(self, tool: str, text: str) -> str:
        """Filter an untrusted tool output before it is placed in the model context."""
        t0 = time.perf_counter()
        seg = Segment(text, Trust.UNTRUSTED, f"tool:{tool}")
        action = "pass"
        if self.cfg.detection:
            score = self.detector.score(text)
            if score >= self.detector.threshold:
                seg.flags.append(f"injection_score={score:.2f}")
                action = "quarantine"
                text = f"[Content from {tool} withheld by security gateway: possible prompt injection]"
                seg = Segment(text, Trust.UNTRUSTED, f"tool:{tool}", seg.flags)
        self.ledger.add(seg)
        out = self.spot.wrap(seg) if self.cfg.spotlight else seg.text
        if self.cfg.logging:
            self.logger.log(event="tool_output", tool=tool, action=action, flags=seg.flags,
                            latency_ms=(time.perf_counter() - t0) * 1000)
        return out

    # ----------------------------------------------------------------- outputs
    def tool_call(self, tool: str, args: dict) -> Decision:
        t0 = time.perf_counter()
        decision, reasons = Decision.ALLOW, []
        if self.cfg.authorisation:
            res = self.policy.check(tool, args, self.ledger)
            decision, reasons = res.decision, res.reasons
        if decision is Decision.ALLOW and self.cfg.output_validation:
            v = self.validator.check(json.dumps(args, default=str), self.ledger.trusted_text())
            if not v.ok:
                decision, reasons = Decision.CONFIRM, [f"output validation: {v.findings}"]
        if self.cfg.logging:
            self.logger.log(event="tool_call", tool=tool, args=args, decision=decision.value,
                            reasons=reasons, latency_ms=(time.perf_counter() - t0) * 1000)
        return decision

    def final_answer(self, text: str) -> str:
        if not self.cfg.output_validation:
            return text
        v = self.validator.check(text, self.ledger.trusted_text(), answer=True)
        if self.cfg.logging:
            self.logger.log(event="final_answer", ok=v.ok, findings=v.findings)
        return text if v.ok else "[Response withheld by security gateway: possible data leakage]"

    def system_prompt_addendum(self) -> str:
        return self.spot.system_note() if self.cfg.spotlight else ""
