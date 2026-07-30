"""Shared bounded decision runner for THOS agent-owned decisions.

Callers provide the decision schema and a semantic validator. Ollama enforces
the JSON shape while the caller validates evidence references, configured
capabilities, source names, and resource bounds. A failed agent decision never
silently turns into a domain-specific deterministic conclusion.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from services.reasoning.ollama_client import generate
from services.runtime_config import get_value


class AgentDecisionError(RuntimeError):
    """Raised when an agent cannot produce a valid decision within its budget."""


Validator = Callable[[dict[str, Any]], dict[str, Any]]


async def decide_json(
    *,
    agent: str,
    system: str,
    prompt: str,
    schema: dict[str, Any],
    validator: Validator,
    attempts: int | None = None,
    num_predict: int | None = None,
    transport_retries: int = 1,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Return one schema- and domain-validated local-model decision."""
    configured_attempts = int(
        get_value("autonomy", "decision_attempts", default=3)
    )
    budget = max(1, min(int(attempts or configured_attempts), 10))
    failures: list[str] = []
    for attempt in range(1, budget + 1):
        repair = ""
        if failures:
            repair = (
                "\n\nYour previous response was rejected by the deterministic "
                f"validator: {failures[-1]}. Re-evaluate the supplied evidence "
                "and return a complete replacement object. Do not invent facts."
            )
        try:
            raw = await generate(
                prompt + repair,
                system=system,
                format=schema,
                agent=agent,
                transport_retries=max(0, int(transport_retries)),
                num_predict=num_predict,
                timeout_seconds=timeout_seconds,
            )
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("response was not a JSON object")
            validated = validator(parsed)
            return {
                **validated,
                "_decision_metadata": {
                    "owner": f"{agent}_model",
                    "attempt": attempt,
                    "degraded": False,
                },
            }
        except Exception as exc:  # bounded model/validation strike handling
            failures.append(str(exc) or exc.__class__.__name__)
    raise AgentDecisionError(
        f"{agent} failed to return a validated decision after {budget} "
        f"attempt(s): {'; '.join(failures)}"
    )
