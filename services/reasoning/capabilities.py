"""Local inference-capability assessment and model recommendations.

Recommendations are advisory facts derived from the configured Ollama memory
budget, visible CPU capacity, installed model metadata, and currently resident
models.  They never download a model or silently change administrator choices.
"""
from __future__ import annotations

import os
import re
from typing import Any


_EMBEDDING_MARKERS = ("embed", "embedding", "bge-", "nomic-")


def _parameter_billions(value: Any) -> float:
    text = str(value or "").strip().upper()
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*B", text)
    return float(match.group(1)) if match else 0.0


def normalized_models(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return generation-capable installed models with comparable metadata."""
    normalized = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("model") or "").strip()
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        family = str(details.get("family") or "").lower()
        marker = f"{name} {family}".lower()
        if not name or any(value in marker for value in _EMBEDDING_MARKERS):
            continue
        normalized.append({
            "name": name,
            "size": max(0, int(item.get("size") or 0)),
            "parameter_billions": _parameter_billions(
                details.get("parameter_size") or item.get("parameter_size")
            ),
            "family": family,
            "quantization": str(details.get("quantization_level") or ""),
            "modified_at": str(item.get("modified_at") or ""),
        })
    return sorted(normalized, key=lambda item: (item["size"], item["name"]))


def resource_snapshot(
    resident_models: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Describe capacity relevant to local inference inside this deployment."""
    budget_gb = max(
        1.0,
        float(os.environ.get("THOS_OLLAMA_MEMORY_BUDGET_GB", "8")),
    )
    resident = [item for item in (resident_models or []) if isinstance(item, dict)]
    resident_bytes = sum(
        max(int(item.get("size") or 0), int(item.get("size_vram") or 0))
        for item in resident
    )
    vram_bytes = sum(int(item.get("size_vram") or 0) for item in resident)
    cpu_count = max(1, int(os.cpu_count() or 1))
    if budget_gb >= 24 and cpu_count >= 12:
        capacity_class = "high"
    elif budget_gb >= 12 and cpu_count >= 6:
        capacity_class = "capable"
    elif budget_gb >= 6 and cpu_count >= 4:
        capacity_class = "balanced"
    else:
        capacity_class = "compact"
    return {
        "capacity_class": capacity_class,
        "logical_cpus_visible": cpu_count,
        "inference_memory_budget_bytes": int(budget_gb * 1024**3),
        "inference_memory_budget_gb": budget_gb,
        "resident_model_bytes": resident_bytes,
        "resident_memory_ratio": round(
            resident_bytes / max(1, int(budget_gb * 1024**3)), 4
        ),
        "accelerator_observed": vram_bytes > 0,
        "resident_vram_bytes": vram_bytes,
        "basis": (
            "Configured Ollama memory budget, CPU visibility, installed model "
            "metadata, and Ollama resident-model telemetry."
        ),
    }


def recommend_models(
    models: list[dict[str, Any]],
    agent_tiers: dict[str, str],
    resources: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Recommend one installed model per agent route without mutating config."""
    candidates = normalized_models(models)
    if not candidates:
        return {}
    budget = max(1, int(resources.get("inference_memory_budget_bytes") or 1))
    # Leave room for KV cache and the inference runtime. Blob sizes are a
    # better cross-model comparison than parameter-name parsing.
    fitting = [item for item in candidates if item["size"] <= budget * 0.60]
    fitting = fitting or candidates[:1]
    fastest = min(fitting, key=lambda item: (item["size"], item["name"]))
    quality = max(
        fitting,
        key=lambda item: (
            item["parameter_billions"], item["size"], item["name"]
        ),
    )
    coding_candidates = [
        item for item in fitting
        if any(marker in item["name"].lower() for marker in ("code", "coder"))
    ]
    coding = max(
        coding_candidates or [quality],
        key=lambda item: (item["parameter_billions"], item["size"]),
    )
    recommendations: dict[str, dict[str, Any]] = {}
    for agent, tier in sorted(agent_tiers.items()):
        if tier in {"fast", "query", "guard"}:
            selected = coding if tier == "query" and coding_candidates else fastest
            role = "latency-sensitive"
        elif tier == "coding":
            selected = coding
            role = "code/schema-sensitive"
        else:
            selected = quality
            role = "quality-sensitive"
        recommendations[str(agent)] = {
            "model": selected["name"],
            "tier": str(tier),
            "reason": (
                f"Selected as the {role} fit from installed generation models "
                f"within 60% of the {resources.get('inference_memory_budget_gb')} GB "
                "inference budget."
            ),
            "estimated_model_bytes": selected["size"],
            "parameter_billions": selected["parameter_billions"],
        }
    return recommendations
