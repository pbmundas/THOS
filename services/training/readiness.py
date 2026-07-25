"""Promotion gates for a cybersecurity fine-tuning run."""
from __future__ import annotations

from pathlib import Path

from services.knowledge.cyber_corpus import load_manifest


def assess_readiness(
    manifest_path: str | Path,
    verified_examples: int,
    retrieval_pass_rate: float,
    grounding_pass_rate: float,
    gpu_vram_gb: float,
    target_parameters_billion: float = 4.0,
) -> dict:
    sources = load_manifest(manifest_path)
    enabled = [source for source in sources if source.enabled]
    required = [source for source in enabled if source.required]
    minimum_vram = 12.0 if target_parameters_billion <= 4 else 24.0
    gates = {
        "required_sources_declared": bool(required),
        "verified_examples_at_least_250": verified_examples >= 250,
        "retrieval_pass_rate_at_least_0_90": retrieval_pass_rate >= 0.90,
        "grounding_pass_rate_at_least_0_98": grounding_pass_rate >= 0.98,
        "training_vram_sufficient": gpu_vram_gb >= minimum_vram,
    }
    blockers = [name for name, passed in gates.items() if not passed]
    return {
        "ready": not blockers,
        "gates": gates,
        "blockers": blockers,
        "enabled_sources": [source.id for source in enabled],
        "target_parameters_billion": target_parameters_billion,
        "minimum_training_vram_gb": minimum_vram,
        "note": (
            "RAG ingestion and evaluation can run on CPU. Weight adaptation must not "
            "start until every gate passes and an SME approves the dataset snapshot."
        ),
    }
