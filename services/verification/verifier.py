"""Evidence-first verifier for analyst-facing findings.

This deterministic critic is intentionally run even when an escalation model
is offline: it prevents invalid record citations from being presented as hard
evidence. It supplies a stable safety floor for the optional Tier-2 model.
"""
from __future__ import annotations

import re
from services.orchestration.state import HuntState

_REF = re.compile(r"ref:\s*([^\)]+)", re.IGNORECASE)
_REF_LIST = re.compile(r"^\d+(?:\s*-\s*\d+)?(?:\s*,\s*\d+(?:\s*-\s*\d+)?)*$")


def _expand_references(value: str) -> list[int] | None:
    """Parse one ref, comma-separated refs, or compact inclusive ranges."""
    prefix = value.split(" (", 1)[0].strip()
    if not _REF_LIST.fullmatch(prefix):
        return None
    expanded = []
    for token in prefix.split(","):
        token = token.strip()
        if "-" not in token:
            expanded.append(int(token))
            continue
        start_text, end_text = token.split("-", 1)
        start, end = int(start_text.strip()), int(end_text.strip())
        if end < start or end - start > 100:
            return None
        expanded.extend(range(start, end + 1))
    return expanded


async def verify_findings_node(state: HuntState) -> dict:
    findings = state.get("findings") or ""
    log_count = len(state.get("processed_logs") or [])
    invalid_refs, checked = [], 0
    for ref in _REF.findall(findings):
        ref = ref.strip()
        if ref.lower() == "histogram":
            checked += 1
            continue
        numbers = _expand_references(ref)
        if numbers is None:
            invalid_refs.append(ref)
            continue
        for number in numbers:
            checked += 1
            if number < 0 or number >= log_count:
                invalid_refs.append(str(number))
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
