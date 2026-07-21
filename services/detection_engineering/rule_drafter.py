"""Draft a conservative Sigma proposal; never writes into the live ruleset."""
import hashlib
import re
from services.orchestration.state import HuntState


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:60] or "thos_hunt_proposal"


def detection_rule_digest(rule_yaml: str) -> str:
    """Bind an approval to the exact normalized proposal content."""
    return hashlib.sha256(rule_yaml.strip().encode("utf-8")).hexdigest()


def detection_rule_approval_error(approval: dict | None, hunt_id: str,
                                  rule_yaml: str) -> str | None:
    """Return why an approval cannot authorize promotion, or None."""
    if not approval:
        return "a persisted human approval is required"
    if str(approval.get("hunt_id")) != hunt_id:
        return "approval belongs to a different hunt"
    if approval.get("approval_type") != "detection_rule":
        return "approval is not for detection-rule promotion"
    if approval.get("status") != "approved" or not approval.get("decided_by"):
        return "detection rule has not been approved by a human"
    if approval.get("artifact_hash") != detection_rule_digest(rule_yaml):
        return "approved rule content does not match this proposal"
    return None


async def draft_detection_rule_node(state: HuntState) -> dict:
    if (state.get("verifier_result") or {}).get("status") != "passed" or state.get("sigma_matched_count", 0) > 0:
        return {"proposed_detection_rule": None}
    keywords = [str(value) for value in ((state.get("enrichment") or {}).get("llm_indicator_keywords") or [])[:4] if str(value).strip()]
    if not keywords:
        return {"proposed_detection_rule": None}
    selection = "\n".join("      - '" + word.replace("'", "''") + "'" for word in keywords)
    technique_id = state.get("technique_id") or ""
    lines = [
        f"title: THOS proposal: {state.get('technique_name') or 'Hunt-derived detection'}",
        f"id: {_slug('thos_proposal_' + technique_id + '_' + state.get('hunt_id', ''))}",
        "status: experimental",
        "description: Drafted from a verifier-passed hunt. Requires analyst review before promotion.",
        "author: THOS Detection Engineering Agent",
        "logsource:", "  product: windows", "detection:", "  selection:", "    detail|contains:", selection,
        "  condition: selection", "falsepositives:", "  - Legitimate administrative activity", "level: medium",
    ]
    proposal = "\n".join(lines) + "\n"
    digest = detection_rule_digest(proposal)
    approval_id = None
    try:
        from services.observability import audit
        approval = await audit.create_approval(
            state.get("hunt_id"),
            "Approve this exact detection-rule proposal for staging",
            approval_type="detection_rule",
            artifact_hash=digest,
        )
        if approval:
            approval_id = str(approval.get("approval_id"))
    except Exception:
        # The proposal remains a draft when the approval store is unavailable;
        # promotion will fail closed because it requires a persisted approval.
        pass
    return {
        "proposed_detection_rule": proposal,
        "proposed_detection_rule_hash": digest,
        "approval_id": approval_id,
        "human_approval_required": True,
        "human_approval_status": "pending" if approval_id else "unavailable",
        "escalation_reason": "Detection rules require human approval before promotion",
    }
