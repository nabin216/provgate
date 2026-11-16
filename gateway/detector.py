"""C1 - Prompt-injection detection.

Two detectors are provided so they can be compared in the evaluation:

* RuleDetector  - transparent, weighted heuristic rules (no training data needed).
* MLDetector    - TF-IDF (word + character n-grams) + logistic regression, trained
                  on a development split and applied to held-out data.

Both expose .score(text) -> float in [0, 1] and .predict(text) -> bool.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Rule-based detector
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    weight: float


def _r(name: str, regex: str, weight: float) -> Rule:
    return Rule(name, re.compile(regex, re.IGNORECASE | re.DOTALL), weight)


DEFAULT_RULES: list[Rule] = [
    # Explicit override of earlier instructions
    _r("override", r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,25}\b(instruction|prompt|task|rule|direction)s?", 0.9),
    # Fake system / role markers
    _r("fake_role", r"(###\s*\(?system|<\|?(system|im_start|assistant)\|?>|\[(system|admin)\]|\bsystem[_ ]message\b|\bsystem prompt\b)", 0.8),
    # Pseudo-tags used to frame injected instructions
    _r("pseudo_tag", r"</?\s*(information|instructions?|important|admin|override)\s*>", 0.6),
    # Message addressed to the model / assistant
    _r("addressed_to_model", r"\b(to you|dear|hey|attention)\b.{0,30}\b(ai|assistant|language model|llm|agent|model|chatbot)\b", 0.6),
    # Urgency / priority framing
    _r("urgency", r"\b(important!+|urgent|immediately|before you (can )?(solve|do|complete|continue)|first,? (you must|please))\b", 0.45),
    # Task-switching phrasing
    _r("task_switch", r"\b(instead|new (task|instruction)s?|your (new|real|actual) (task|goal|instruction)|after you do that|do the following)\b", 0.4),
    # Hidden-instruction cues
    _r("secrecy", r"\b(do not|don't|never) (tell|inform|mention|reveal|notify)\b.{0,30}\b(user|anyone|them)\b", 0.5),
    # Exfiltration-style requests (send / forward data to external party)
    _r("exfil_verb", r"\b(send|forward|email|transfer|post|share|upload)\b.{0,60}\b(password|credential|security code|api key|token|iban|account|balance|file|messages?|all )\b", 0.3),
    # Imperative TODO-style markers
    _r("todo_marker", r"(^|\s)(todo|note to (ai|assistant|agent))\s*:", 0.35),
]


def _looks_base64(text: str) -> bool:
    for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", text):
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8", "ignore")
            if re.search(r"\b(ignore|instruction|send|password)\b", decoded, re.I):
                return True
        except Exception:
            continue
    return False


@dataclass
class RuleDetector:
    rules: list[Rule] = field(default_factory=lambda: list(DEFAULT_RULES))
    threshold: float = 0.5

    def explain(self, text: str) -> list[str]:
        hits = [r.name for r in self.rules if r.pattern.search(text)]
        if _looks_base64(text):
            hits.append("base64_payload")
        return hits

    def score(self, text: str) -> float:
        # noisy-OR combination of fired rules
        p_clean = 1.0
        for r in self.rules:
            if r.pattern.search(text):
                p_clean *= (1.0 - r.weight)
        if _looks_base64(text):
            p_clean *= 0.2
        return 1.0 - p_clean

    def predict(self, text: str) -> bool:
        return self.score(text) >= self.threshold


# ---------------------------------------------------------------------------
# Lightweight ML detector
# ---------------------------------------------------------------------------

class MLDetector:
    def __init__(self, threshold: float = 0.5):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import FeatureUnion, Pipeline

        self.threshold = threshold
        self.model = Pipeline([
            ("feats", FeatureUnion([
                ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
                ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
            ])),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0)),
        ])

    def fit(self, texts, labels):
        self.model.fit(list(texts), list(labels))
        return self

    def score(self, text: str) -> float:
        return float(self.model.predict_proba([text])[0, 1])

    def score_many(self, texts):
        return self.model.predict_proba(list(texts))[:, 1]

    def predict(self, text: str) -> bool:
        return self.score(text) >= self.threshold
