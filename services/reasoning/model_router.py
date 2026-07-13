"""On-prem model tier routing for THOS agents.

All defaults preserve the existing single-Ollama deployment.  Operators can
point tiers to separate on-prem Ollama/vLLM endpoints without changing agent
code.  No hosted inference endpoints are used or supported here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelTarget:
    tier: str
    host: str
    model: str
    num_ctx: int
    num_predict: int


_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
_DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:4b")

_AGENT_TIERS = {
    "query_gen": "fast", "indicator_deriver": "fast", "communication": "fast",
    "supervisor": "reasoning", "reasoning": "reasoning", "coverage_gap": "reasoning",
    "verifier": "verifier", "detection_engineering": "coding", "guardrail": "guard",
}


def target_for(agent: str) -> ModelTarget:
    """Return the local model endpoint and limits for an agent.

    Environment names intentionally remain simple: ``THOS_MODEL_FAST`` and
    ``THOS_OLLAMA_FAST_HOST`` etc. A missing tier config safely falls back to
    the original OLLAMA_MODEL/OLLAMA_HOST rather than breaking hunts.
    """
    tier = _AGENT_TIERS.get(agent, "reasoning")
    suffix = tier.upper()
    return ModelTarget(
        tier=tier,
        host=os.environ.get(f"THOS_OLLAMA_{suffix}_HOST", _DEFAULT_HOST).rstrip("/"),
        model=os.environ.get(f"THOS_MODEL_{suffix}", _DEFAULT_MODEL),
        num_ctx=int(os.environ.get(f"THOS_{suffix}_NUM_CTX", "8192")),
        num_predict=int(os.environ.get(f"THOS_{suffix}_NUM_PREDICT", "1024")),
    )
