"""C3 - Least-privilege tool authorisation.

Two checks are applied to every tool call the model proposes:

1. Task-scoped allow-list (intent check)
   Read-only tools are always permitted.  A state-changing ("write") tool is only
   permitted if the *trusted* user request expresses an intent that needs it.

2. Argument provenance (taint check)
   For high-impact tools, "destination" arguments (recipients, IBANs, URLs, user
   names, passwords) must be traceable to trusted context.  If untrusted content
   is present in the context and the value does not appear in trusted text, the
   call is escalated to the human for confirmation instead of being executed.

Decision values: ALLOW, CONFIRM (human-in-the-loop), DENY.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .context import ContextLedger


class Decision(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


@dataclass
class ToolSpec:
    name: str
    write: bool = False
    intent: str | None = None              # regex over the trusted user request
    sensitive_args: tuple[str, ...] = ()   # destination-like arguments


def _spec(name, intent=None, sensitive=()):
    return ToolSpec(name, write=intent is not None, intent=intent, sensitive_args=tuple(sensitive))


# Policy catalogue for the simulated tools (AgentDojo tool names are used so the
# same policy can be replayed against the benchmark's ground-truth traces).
CATALOGUE: dict[str, ToolSpec] = {s.name: s for s in [
    # ---- e-mail / files / calendar
    _spec("send_email", r"\b(e-?mails?|send|reply|forward|mail)\b", ("recipients", "cc", "bcc")),
    _spec("delete_email", r"\b(delete|remove)\b"),
    _spec("create_calendar_event", r"\b(create|schedule|add|book|organi[sz]e|set ?up|event|meeting|reminder|lunch|dinner)\b", ("participants",)),
    _spec("cancel_calendar_event", r"\bcancel"),
    _spec("reschedule_calendar_event", r"\b(reschedule|move|postpone|change)\b"),
    _spec("add_calendar_event_participants", r"\b(add|invite|participants?)\b", ("participants",)),
    _spec("append_to_file", r"\b(append|add|update|write)\b"),
    _spec("create_file", r"\b(create|write|save|make)\b"),
    _spec("delete_file", r"\b(delete|remove|free up)\b"),
    _spec("share_file", r"\bshare", ("email",)),
    # ---- travel
    _spec("reserve_hotel", r"\b(reserve|book|reservation)"),
    _spec("reserve_car_rental", r"\b(reserve|book|reservation|rent)"),
    _spec("reserve_restaurant", r"\b(reserve|book|reservation)"),
    # ---- banking
    # "send" alone is not enough ("send me a summary"); it needs a money context
    _spec("send_money", r"\b(pay|paid|payments?|transfer|refund|money|bills?|rent)\b"
                        r"|\bsend\b[^.?!]{0,60}\b(back|difference|amount|money|funds|\d)", ("recipient",)),
    _spec("schedule_transaction", r"\b(schedule|recurring|standing|set ?up)\b", ("recipient",)),
    _spec("update_scheduled_transaction", r"\b(update|change|adjust|modify|rent)\b", ("recipient",)),
    _spec("update_password", r"\bpassword\b", ("password",)),
    _spec("update_user_info", r"\b(update|change|address|moved|info)\b"),
    # ---- slack / web
    _spec("add_user_to_channel", r"\b(add|invite)\b", ("user",)),
    _spec("send_direct_message", r"\b(message|dm|send|tell|reply|write)\b", ("recipient",)),
    _spec("send_channel_message", r"\b(post|message|send|channel|write)\b"),
    _spec("invite_user_to_slack", r"\binvite\b", ("user", "user_email")),
    _spec("remove_user_from_slack", r"\b(remove|kick)\b", ("user",)),
    _spec("post_webpage", r"\b(post|publish|website|webpage|upload)\b", ("url",)),
]}

# Read-only tools that can still be used as an egress channel (data in the URL)
EGRESS_READ_TOOLS = {"get_webpage": ("url",)}

# M2: the user explicitly hands authority to external content
# ("do the actions specified in the email", "follow the instructions precisely",
#  "do all the tasks on my TODO list at <url>").
DELEGATION_RE = re.compile(
    r"\b(do|perform|complete|carry out|follow|execute)\b[^.?!]{0,40}?"
    r"\b(actions?|tasks?|instructions?|to-?dos?)\b[^.?!]{0,60}?"
    r"\b(specified|listed|precisely|in the (e-?mail|file|message|document|note)|on my|at|from)\b",
    re.IGNORECASE)


MESSAGE_ARGS = ("body", "content", "subject", "description")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s'\"<>]+", re.IGNORECASE)


def normalise_identity(v: Any) -> str:
    """Canonical form of an e-mail address, user name or URL for M1 lookups."""
    s = str(v).strip().lower()
    s = re.sub(r"^https?://", "", s).rstrip("/")
    return s.lstrip("@")


def _norm(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        out = []
        for x in v:
            out += _norm(x)
        return out
    return [str(v).strip().lower()]


def _in_trusted(value: str, trusted: str) -> bool:
    """The value occurs in trusted text as a whole token: not as part of a longer
    word or number ("bob" does not match "bobby", "100" does not match "1000")."""
    if not value:
        return True
    value = re.sub(r"^https?://", "", value).rstrip("/")
    if not value:
        return True
    return re.search(r"(?<![a-z0-9])" + re.escape(value) + r"(?![a-z0-9])", trusted) is not None


@dataclass
class PolicyResult:
    decision: Decision
    reasons: list[str] = field(default_factory=list)


@dataclass
class PolicyEngine:
    use_intent: bool = True
    use_provenance: bool = True
    catalogue: dict[str, ToolSpec] = field(default_factory=lambda: dict(CATALOGUE))
    trusted_ids: set[str] = field(default_factory=set)   # M1 registry (normalised)
    delegated: bool = False                               # M2: set per session

    def check(self, tool: str, args: dict, ledger: ContextLedger) -> PolicyResult:
        trusted = ledger.trusted_text().lower()
        spec = self.catalogue.get(tool)
        reasons: list[str] = []

        if spec is None and tool not in EGRESS_READ_TOOLS:
            return PolicyResult(Decision.ALLOW, ["read-only tool"])

        # 1. intent / allow-list
        needs_confirm = False
        if self.use_intent and spec is not None and spec.write:
            if not re.search(spec.intent, trusted, re.IGNORECASE):
                if not self.delegated:
                    return PolicyResult(Decision.DENY, [f"'{tool}' not required by the user request"])
                # M2: authority was delegated to external content -> ask, do not deny
                needs_confirm = True
                reasons.append(f"delegated task: '{tool}' not named in the user request")

        # 2. provenance of destination arguments
        via_m1 = False
        if self.use_provenance and ledger.has_untrusted():
            sens = spec.sensitive_args if spec is not None else EGRESS_READ_TOOLS[tool]
            for a in sens:
                for v in _norm(args.get(a)):
                    if _in_trusted(v, trusted):
                        continue
                    if self.trusted_ids and normalise_identity(v) in self.trusted_ids:
                        via_m1 = True   # M1: a contact the user vouches for
                        continue
                    reasons.append(f"argument '{a}'='{v}' not found in trusted context")
                    needs_confirm = True

        # M1 guard: a recipient accepted only because they are a trusted contact
        # must not receive links that came from untrusted content (insider phishing:
        # "send this link to Alice"). Links in the message must be in trusted text.
        if via_m1:
            for a in MESSAGE_ARGS:
                for url in URL_RE.findall(str(args.get(a) or "")):
                    if not _in_trusted(url.lower().rstrip(".,;)"), trusted):
                        reasons.append(f"link '{url}' in '{a}' not found in trusted context (M1 recipient)")
                        needs_confirm = True

        if needs_confirm:
            return PolicyResult(Decision.CONFIRM, reasons)
        return PolicyResult(Decision.ALLOW, reasons or ["policy satisfied"])
