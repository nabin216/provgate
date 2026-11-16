"""B2 with long tool outputs scored in 512-token windows.

AgentDojo 0.1.35's TransformersBasedPIDetector passes the whole tool output to
protectai/deberta-v3-base-prompt-injection-v2 in one call, without truncation.
DeBERTa's attention memory grows with the square of the input length, so a long
output (a full inbox or channel history) used more than 10 GB of RAM on our CPU
host and the process was killed. The model was trained on inputs of at most 512
tokens, so we score each 500-token window (50-token overlap) and flag the
output if ANY window is classified as an injection. Detection is unchanged for
outputs that fit in one window, and long outputs are scored at the length the
model was trained for.
"""
from __future__ import annotations

from agentdojo.agent_pipeline.pi_detector import TransformersBasedPIDetector

WINDOW = 500
STRIDE = 450


def windows(ids: list[int], window: int = WINDOW, stride: int = STRIDE) -> list[list[int]]:
    if len(ids) <= window:
        return [ids]
    out = []
    for start in range(0, len(ids), stride):
        out.append(ids[start:start + window])
        if start + window >= len(ids):
            break
    return out


class ChunkedPIDetector(TransformersBasedPIDetector):
    def detect(self, tool_output: str) -> tuple[bool, float]:
        tok = self.pipeline.tokenizer
        ids = tok(tool_output, add_special_tokens=False)["input_ids"]
        chunks = [tok.decode(w) for w in windows(ids)] if ids else [tool_output]
        results = self.pipeline(chunks, truncation=True, max_length=512, batch_size=1)
        scores = [r["score"] if r["label"] == self.safe_label else 1 - r["score"] for r in results]
        safety = min(scores)
        return safety < self.threshold, safety
