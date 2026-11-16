"""C4 - Output validation.

Checks final answers and outgoing tool arguments for exfiltration patterns before
they leave the system.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

PATTERNS = {
    "markdown_image_exfil": re.compile(r"!\[[^\]]*\]\(https?://[^)]+[?&][^)]*=", re.I),
    "url_with_data_param": re.compile(r"https?://\S+[?&](q|data|d|payload|secret|token)=\S{8,}", re.I),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "password_disclosure": re.compile(r"\b(password|passcode|pwd)\b\s*(is|:|=)\s*\S+", re.I),
    "security_code": re.compile(r"\b(security|verification|2fa|otp|one[- ]time) code\b.{0,20}\b\d{4,8}\b", re.I),
    "api_key": re.compile(r"\b(sk|pk|api|key)[-_][A-Za-z0-9]{16,}\b"),
}


# Final answers go to the user, so a secret the user's own request asks for
# ("what is my security code?") is not a leak. Never exempt for tool arguments,
# and never for image beacons (rendered, i.e. sent, without the user acting).
REQUESTED = {
    "security_code": re.compile(r"\b(code|otp|2fa|pin)\b", re.I),
    "password_disclosure": re.compile(r"\b(password|passcode)\b", re.I),
    "url_with_data_param": re.compile(r"\b(link|url)\b", re.I),
    "api_key": re.compile(r"\b(api key|key|token)\b", re.I),
    "iban": re.compile(r"\b(iban|account number)\b", re.I),
}


@dataclass
class ValidationResult:
    ok: bool
    findings: list[str] = field(default_factory=list)


class OutputValidator:
    def __init__(self, protected_values: list[str] | None = None):
        # e.g. secrets seeded into the test environment
        self.protected = [p.lower() for p in (protected_values or [])]

    def check(self, text: str, trusted_text: str = "", answer: bool = False) -> ValidationResult:
        """answer=True: `text` is the final answer to the user; categories the
        user's request (part of trusted_text) asks for are not findings."""
        findings = []
        low = text.lower()
        for name, pat in PATTERNS.items():
            if answer and name in REQUESTED and REQUESTED[name].search(trusted_text):
                continue
            for m in pat.finditer(text):
                if m.group(0).lower() not in trusted_text.lower():
                    findings.append(name)
                    break
        for p in self.protected:
            if p and p in low:
                findings.append("protected_value")
        return ValidationResult(ok=not findings, findings=findings)
