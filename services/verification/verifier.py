"""Evidence-first verifier for analyst-facing findings.

This deterministic critic is intentionally run even when an escalation model
is offline: it prevents invalid record citations from being presented as hard
evidence. It supplies a stable safety floor for the optional Tier-2 model.
"""
from __future__ import annotations

import re
from services.orchestration.state import HuntState

_REF = re.compile(r"ref:\s*([^\)]+)", re.IGNORECASE)


async def verify_findings_node(state: HuntState) -> dict:
    findings = state.get("findings") or ""
    log_count = len(state.get("processed_logs") or [])
    invalid_refs, checked = [], 0
    for ref in _REF.findall(findings):
        ref = ref.strip()
        if ref.lower() == "histogram":
            checked += 1
            continue
        try:
            number = int(ref)
            checked += 1
            if number < 0 or number >= log_count:
                invalid_refs.append(ref)
        except ValueError:
            invalid_refs.append(ref)
    no_citation = bool(findings.strip()) and checked == 0
    failed = bool(invalid_refs or no_citation)
    result = {"status": "failed" if failed else "passed", "checked_citations": checked,
              "invalid_references": invalid_refs,
              "reason": "finding output had no verifiable citations" if no_citation else ("invalid record references" if invalid_refs else "all cited references are in range")}
    approval_id = None
    case_id = None
    if failed:
        findings += "\n\n- [circumstantial] Verifier warning: one or more finding citations could not be validated; analyst review is required."
        try:
            from services.observability import audit
            approval = await audit.create_approval(
                state.get("hunt_id"),
                result["reason"],
            )
            if approval:
                approval_id = str(approval.get("approval_id"))
            
            case = await audit.create_case(
                state.get("hunt_id"),
                f"Analyst review required: {state.get('technique_name') or 'THOS hunt'}",
                "high",
                state.get("hunter_name") or "anonymous",
                state.get("reasoning_summary"),
                "thos-verifier",
            )
            if case:
                case_id = str(case.get("case_id"))
        except Exception:
            pass

    return {"findings": findings, "verifier_result": result, "human_approval_required": failed,
            "human_approval_status": "pending" if failed else None,
            "escalation_reason": result["reason"] if failed else None,
            "approval_id": approval_id, "case_id": case_id}
