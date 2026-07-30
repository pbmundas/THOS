from services.training.readiness import assess_readiness


MANIFEST = "data/knowledge_sources/cybersecurity_sources.json"


def test_current_four_gb_class_hardware_fails_training_gate():
    result = assess_readiness(
        MANIFEST,
        verified_examples=500,
        retrieval_pass_rate=0.95,
        grounding_pass_rate=0.99,
        gpu_vram_gb=4,
        target_parameters_billion=4,
    )

    assert result["ready"] is False
    assert set(result["blockers"]) == {
        "cybersecurity_capability_suite_passed",
        "frozen_model_and_evaluation_identified",
        "cybersecurity_sme_approved",
        "training_vram_sufficient",
    }
    assert result["minimum_training_vram_gb"] == 12


def test_all_quality_and_resource_gates_are_mandatory():
    result = assess_readiness(
        MANIFEST,
        verified_examples=249,
        retrieval_pass_rate=0.89,
        grounding_pass_rate=0.97,
        gpu_vram_gb=24,
    )

    assert result["ready"] is False
    assert set(result["blockers"]) == {
        "verified_examples_at_least_250",
        "retrieval_pass_rate_at_least_0_90",
        "grounding_pass_rate_at_least_0_98",
        "cybersecurity_capability_suite_passed",
        "frozen_model_and_evaluation_identified",
        "cybersecurity_sme_approved",
    }


def test_capability_report_and_sme_approval_are_required_for_readiness():
    capability = {
        "ready": True,
        "model_digest": "sha256:abc",
        "dataset_snapshot_id": "dataset-v1",
        "evaluation_snapshot_id": "eval-v1",
    }
    result = assess_readiness(
        MANIFEST,
        verified_examples=500,
        retrieval_pass_rate=0.95,
        grounding_pass_rate=0.99,
        gpu_vram_gb=24,
        capability_report=capability,
        sme_approved=True,
    )

    assert result["ready"] is True
