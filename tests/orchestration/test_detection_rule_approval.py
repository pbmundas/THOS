import asyncio
from unittest.mock import AsyncMock

from services.detection_engineering.rule_drafter import (
    detection_rule_approval_error,
    detection_rule_digest,
    draft_detection_rule_node,
)
from services.observability import audit


RULE = """title: Test proposal
status: experimental
detection:
  condition: selection
"""


def test_rule_approval_is_bound_to_hunt_type_status_and_exact_content():
    approval = {
        "hunt_id": "hunt-1",
        "approval_type": "detection_rule",
        "status": "approved",
        "decided_by": "analyst@example.test",
        "artifact_hash": detection_rule_digest(RULE),
    }

    assert detection_rule_approval_error(approval, "hunt-1", RULE) is None
    assert "different hunt" in detection_rule_approval_error(approval, "hunt-2", RULE)
    assert "does not match" in detection_rule_approval_error(
        approval, "hunt-1", RULE + "level: high\n"
    )


def test_rule_drafter_creates_pending_approval_for_exact_digest(monkeypatch):
    create_approval = AsyncMock(return_value={"approval_id": "approval-1"})
    monkeypatch.setattr(audit, "create_approval", create_approval)

    state = {
        "hunt_id": "hunt-1",
        "verifier_result": {"status": "passed"},
        "sigma_matched_count": 0,
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "enrichment": {"llm_indicator_keywords": ["EncodedCommand"]},
    }
    result = asyncio.run(draft_detection_rule_node(state))

    assert result["human_approval_required"] is True
    assert result["human_approval_status"] == "pending"
    assert result["approval_id"] == "approval-1"
    assert result["proposed_detection_rule_hash"] == detection_rule_digest(
        result["proposed_detection_rule"]
    )
    create_approval.assert_awaited_once_with(
        "hunt-1",
        "Approve this exact detection-rule proposal for staging",
        approval_type="detection_rule",
        artifact_hash=result["proposed_detection_rule_hash"],
    )
