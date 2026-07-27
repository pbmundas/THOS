"""On-prem model tier routing for THOS agents.

All defaults preserve the existing single-Ollama deployment.  Operators can
point tiers to separate on-prem Ollama/vLLM endpoints without changing agent
code.  No hosted inference endpoints are used or supported here.
"""
from __future__ import annotations

import os
from contextvars import ContextVar, Token
from dataclasses import dataclass

from services.runtime_config import get_value


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
    "query_gen": "query", "indicator_deriver": "fast", "communication": "fast",
    "chat": "fast",
    "investigation_specialist": "reasoning",
    "supervisor": "reasoning", "reasoning": "reasoning", "coverage_gap": "reasoning",
    "verifier": "verifier", "detection_engineering": "coding", "guardrail": "guard",
}
_WORKLOAD_CLASS: ContextVar[str] = ContextVar(
    "thos_model_workload_class", default="interactive"
)
_SCHEDULED_REASONING_AGENTS = {
    "reasoning", "supervisor", "coverage_gap", "investigation_specialist"
}


def set_model_workload(workload_class: str) -> Token:
    value = "scheduled" if str(workload_class).lower() == "scheduled" else "interactive"
    return _WORKLOAD_CLASS.set(value)


def reset_model_workload(token: Token) -> None:
    _WORKLOAD_CLASS.reset(token)


def target_for(agent: str) -> ModelTarget:
    """Return the local model endpoint and limits for an agent.

    Environment names intentionally remain simple: ``THOS_MODEL_FAST`` and
    ``THOS_OLLAMA_FAST_HOST`` etc. A missing tier config safely falls back to
    the original OLLAMA_MODEL/OLLAMA_HOST rather than breaking hunts.
    """
    tier = _AGENT_TIERS.get(agent, "reasoning")
    suffix = tier.upper()
    runtime_model = str(get_value("models", "default_model", default="") or "").strip()
    configured_model = os.environ.get(f"THOS_MODEL_{suffix}", _DEFAULT_MODEL)
    # The settings-page default controls quality-sensitive reasoning behavior.
    # Query generation, Ask THOS, communication, and lightweight extraction keep
    # their dedicated low-latency models so changing the default cannot
    # accidentally put the larger reasoning model on a latency-critical path.
    selected_model = configured_model if tier in {"query", "fast"} else (runtime_model or configured_model)
    default_num_ctx = (
        "4096" if tier == "query"
        else ("16384" if tier == "reasoning" else "8192")
    )
    host = os.environ.get(f"THOS_OLLAMA_{suffix}_HOST", _DEFAULT_HOST).rstrip("/")
    model = selected_model
    num_ctx = int(os.environ.get(f"THOS_{suffix}_NUM_CTX", default_num_ctx))
    num_predict = int(os.environ.get(
        f"THOS_{suffix}_NUM_PREDICT",
        "256" if tier == "query" else ("2048" if tier == "reasoning" else "1024"),
    ))
    if _WORKLOAD_CLASS.get() == "scheduled" and agent in _SCHEDULED_REASONING_AGENTS:
        host = os.environ.get("THOS_SCHEDULED_OLLAMA_HOST", host).rstrip("/")
        model = os.environ.get("THOS_SCHEDULED_MODEL", "").strip() or model
        num_ctx = int(os.environ.get("THOS_SCHEDULED_NUM_CTX", str(num_ctx)))
        num_predict = int(
            os.environ.get("THOS_SCHEDULED_NUM_PREDICT", str(num_predict))
        )
    return ModelTarget(
        tier=tier,
        host=host,
        model=model,
        num_ctx=num_ctx,
        num_predict=num_predict,
    )
