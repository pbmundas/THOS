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
    capability_report: dict | None = None,
    sme_approved: bool = False,
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
        "cybersecurity_capability_suite_passed": bool(
            capability_report and capability_report.get("ready") is True
        ),
        "frozen_model_and_evaluation_identified": bool(
            capability_report
            and str(capability_report.get("model_digest") or "").strip()
            and str(capability_report.get("dataset_snapshot_id") or "").strip()
            and str(capability_report.get("evaluation_snapshot_id") or "").strip()
        ),
        "cybersecurity_sme_approved": sme_approved is True,
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
            "start until every gate passes, a frozen domain-balanced capability "
            "evaluation passes, and a cybersecurity SME approves the snapshot. "
            "Passing these gates reduces risk; it does not guarantee zero hallucination."
        ),
    }
