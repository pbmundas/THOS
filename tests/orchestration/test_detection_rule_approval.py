import asyncio

from services.detection_engineering.rule_drafter import (
    detection_rule_digest,
    draft_detection_rule_node,
)


def test_rule_drafter_returns_hashed_draft_without_approval_record():
    state = {
        "hunt_id": "hunt-1",
        "verifier_result": {"status": "passed"},
        "sigma_matched_count": 0,
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "enrichment": {"llm_indicator_keywords": ["EncodedCommand"]},
    }

    result = asyncio.run(draft_detection_rule_node(state))

    assert result["change_control_required"] is True
    assert result["proposed_detection_rule_hash"] == detection_rule_digest(
        result["proposed_detection_rule"]
    )
    assert "approval_id" not in result
    assert "human_approval_required" not in result


def test_rule_drafter_skips_unverified_or_already_detected_hunts():
    unverified = asyncio.run(draft_detection_rule_node({
        "verifier_result": {"status": "failed"},
        "sigma_matched_count": 0,
    }))
    detected = asyncio.run(draft_detection_rule_node({
        "verifier_result": {"status": "passed"},
        "sigma_matched_count": 2,
    }))

    assert unverified["proposed_detection_rule"] is None
    assert detected["proposed_detection_rule"] is None
