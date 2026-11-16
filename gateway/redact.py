"""M3 - record-level injection redaction (a finer-grained C1).

The original C1 withholds a whole tool output when it scores at or above the
threshold. Many tool outputs are collections (an inbox, a channel history, a
list of reviews), so one injected message removes every other record the user
task needs. M3 keeps C1's detector and threshold but changes what is removed:

1. The structured tool result is walked; every string field (an e-mail body,
   a message, a review, a file's content) is a *record*.
2. A record that scores below the threshold is kept unchanged.
3. A flagged record is redacted at passage level: its lines are scored one by
   one and the span from the first to the last flagged line, widened
   by CONTEXT_LINES lines on each side (default 0), is replaced by a marker. If no single line crosses the
   threshold (the evidence is spread over the record), the whole record is
   replaced. If what remains of the record still scores at or above the
   threshold, the whole record is replaced.
4. Safety net: if no record was redacted although the whole output was
   flagged, or if the redacted output as a whole still scores at or above the
   threshold, the caller falls back to withholding the whole output (original
   C1 behaviour).

What the model sees is therefore always below C1's threshold: each remaining
record and the output as a whole. M3 removes no more than the original C1.
Its residual risk is an instruction line that lies outside the span between
flagged lines and is not flagged itself; the offline evaluation counts an
attack as visible whenever the attacker's goal text survives (live/scripted.py).
"""
from __future__ import annotations

from typing import Any

MARK = "[{what} removed by security gateway: possible prompt injection]"
CONTEXT_LINES = 0   # 1 removed legitimate neighbouring lines (e.g. the IBAN in a bill); leakage is measured instead


def to_plain(obj: Any) -> Any:
    """Pydantic models -> dicts, recursively; everything else unchanged."""
    if hasattr(obj, "model_dump"):
        return to_plain(obj.model_dump())
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(x) for x in obj]
    return obj


def redact_text(text: str, detector) -> tuple[str, bool]:
    """Redact one record. Returns (new_text, changed)."""
    thr = detector.threshold
    if detector.score(text) < thr:
        return text, False
    lines = text.split("\n")
    idx = [i for i, ln in enumerate(lines) if ln.strip()]
    flagged = [i for i in idx if detector.score(lines[i]) >= thr]
    if len(idx) <= 1 or not flagged:
        return MARK.format(what="Text"), True
    # widen by CONTEXT_LINES non-empty lines on each side
    lo_pos = max(idx.index(flagged[0]) - CONTEXT_LINES, 0)
    hi_pos = min(idx.index(flagged[-1]) + CONTEXT_LINES, len(idx) - 1)
    lo, hi = idx[lo_pos], idx[hi_pos]
    new = "\n".join(lines[:lo] + [MARK.format(what="Passage")] + lines[hi + 1:])
    if detector.score(new) >= thr:
        return MARK.format(what="Text"), True
    return new, True


def redact_obj(obj: Any, detector) -> tuple[Any, int]:
    """Walk a plain structure; returns (redacted copy, number of records changed)."""
    if isinstance(obj, str):
        new, changed = redact_text(obj, detector)
        return new, int(changed)
    if isinstance(obj, dict):
        out, n = {}, 0
        for k, v in obj.items():
            out[k], c = redact_obj(v, detector)
            n += c
        return out, n
    if isinstance(obj, list):
        out, n = [], 0
        for v in obj:
            nv, c = redact_obj(v, detector)
            out.append(nv)
            n += c
        return out, n
    return obj, 0
