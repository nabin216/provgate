"""Builds the pipeline for each configuration in Table VI of the paper.

B0  no defence                     (AgentDojo pipeline, defense=None)
B1  tool filter                    (AgentDojo built-in)
B2  transformer PI detector        (AgentDojo built-in; needs agentdojo[transformers])
B3  spotlighting with delimiting   (AgentDojo built-in)
B4  repeat user prompt             (AgentDojo built-in)
G1  detection only (C1)
G2  tool allow-list only (C3a)
G3  allow-list + provenance (C3)
G4  full gateway (C1+C2+C3+C4)
G4-noC2   G4 without spotlighting
G4-deny   G4 with deny-on-confirm instead of oracle confirmation

RQ3 mitigations (Table VIII):
G3-M1     G3 + trusted contacts            G1-M3    G1 with record-level redaction
G3-M2     G3 + delegated-task mode         G4-M3    G4 with record-level redaction
G3+       G3 + M1 + M2                     G4+      G4 + M1 + M2 + M3
G3+-deny  G3+ with deny-on-confirm         G4+-deny G4+ with deny-on-confirm
G5        recommended: G4+ without spotlighting (ledger kept)   G5-deny

B2 scores long tool outputs in 512-token windows (live/chunked_pi.py).

Every configuration uses the same LLM element, the benchmark's default system
message and the same loop limit, so the only difference is the defence.
"""
from __future__ import annotations

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor, tool_result_to_str

from gateway import GatewayConfig

from .elements import GatewayFinalAnswer, GatewayInit, GatewayToolsExecutor

BASELINES = {
    "B0": None,
    "B1": "tool_filter",
    "B2": "transformers_pi_detector",
    "B3": "spotlighting_with_delimiting",
    "B4": "repeat_user_prompt",
}

# name: (GatewayConfig kwargs, use_intent, use_provenance, confirm policy)
GATEWAY = {
    "G1": (dict(detection=True, spotlight=False, authorisation=False, output_validation=False), False, False, "oracle"),
    "G2": (dict(detection=False, spotlight=False, authorisation=True, output_validation=False), True, False, "oracle"),
    "G3": (dict(detection=False, spotlight=False, authorisation=True, output_validation=False), True, True, "oracle"),
    "G4": (dict(detection=True, spotlight=True, authorisation=True, output_validation=True), True, True, "oracle"),
    "G4-noC2": (dict(detection=True, spotlight=False, authorisation=True, output_validation=True), True, True, "oracle"),
    "G4-deny": (dict(detection=True, spotlight=True, authorisation=True, output_validation=True), True, True, "deny"),
    "G3-deny": (dict(detection=False, spotlight=False, authorisation=True, output_validation=False), True, True, "deny"),
}

# RQ3 mitigations: same controls as the base configuration plus M1 / M2 / M3
_G1 = dict(detection=True, spotlight=False, authorisation=False, output_validation=False)
_G3 = dict(detection=False, spotlight=False, authorisation=True, output_validation=False)
_G4 = dict(detection=True, spotlight=True, authorisation=True, output_validation=True)
_M1 = dict(trusted_contacts=True)
_M2 = dict(delegation_mode=True)
_M3 = dict(redaction="record")
GATEWAY.update({
    "G3-M1": ({**_G3, **_M1}, True, True, "oracle"),
    "G3-M2": ({**_G3, **_M2}, True, True, "oracle"),
    "G3+": ({**_G3, **_M1, **_M2}, True, True, "oracle"),
    "G3+-deny": ({**_G3, **_M1, **_M2}, True, True, "deny"),
    "G1-M3": ({**_G1, **_M3}, False, False, "oracle"),
    "G4-M3": ({**_G4, **_M3}, True, True, "oracle"),
    "G4+": ({**_G4, **_M1, **_M2, **_M3}, True, True, "oracle"),
    "G4+-deny": ({**_G4, **_M1, **_M2, **_M3}, True, True, "deny"),
    # Recommended configuration: G4+ without spotlighting/datamarking (the C2
    # ledger stays: it supplies trusted text to C3). Live, spotlighting added no
    # security and datamarking cost benign utility.
    "G5": ({**_G4, "spotlight": False, **_M1, **_M2, **_M3}, True, True, "oracle"),
    "G5-deny": ({**_G4, "spotlight": False, **_M1, **_M2, **_M3}, True, True, "deny"),
})

ALL_CONFIGS = list(BASELINES) + list(GATEWAY)
MAX_ITERS = 15  # AgentDojo default


def build(config: str, llm, system_message: str | None = None):
    system_message = system_message or load_system_message(None)
    if config == "B2":
        from .chunked_pi import ChunkedPIDetector
        p = AgentPipeline([
            SystemMessage(system_message),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(tool_result_to_str),
                                ChunkedPIDetector(model_name="protectai/deberta-v3-base-prompt-injection-v2",
                                                  safe_label="SAFE", threshold=0.5, mode="message"),
                                llm]),
        ])
    elif config in BASELINES:
        p = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id=None, defense=BASELINES[config],
                                                     system_message_name=None, system_message=system_message))
    elif config in GATEWAY:
        kw, intent, prov, policy = GATEWAY[config]
        cfg = GatewayConfig(name=config, logging=True, **kw)
        p = AgentPipeline([
            SystemMessage(system_message),
            InitQuery(),
            GatewayInit(cfg, use_intent=intent, use_provenance=prov),
            llm,
            ToolsExecutionLoop([GatewayToolsExecutor(confirm_policy=policy), llm], max_iters=MAX_ITERS),
            GatewayFinalAnswer(),
        ])
    else:
        raise ValueError(f"unknown config {config!r}; choose from {ALL_CONFIGS}")
    # the important_instructions attack looks the model name up in pipeline.name
    p.name = f"{llm.name}|{config}"
    return p
