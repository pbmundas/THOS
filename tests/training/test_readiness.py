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
    assert result["blockers"] == ["training_vram_sufficient"]
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
    }
