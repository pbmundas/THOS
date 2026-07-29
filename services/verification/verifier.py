"""Fail-closed evidence-reference verifier for analyst-facing findings."""
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
    logs = state.get("processed_logs") or []
    log_count = len(logs)
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
    result = {
        "status": "failed" if failed else "passed",
        "checked_citations": checked,
        "invalid_references": invalid_refs,
        "repaired_references": [],
        "reason": (
            "finding output had no verifiable citations"
            if no_citation
            else "invalid record references"
            if invalid_refs
            else "all cited references are in range"
        ),
    }
    case_id = None
    review_required = failed
    review_reason = result["reason"] if failed else None
    if review_required:
        try:
            from services.observability import audit
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

    return {
        "findings": findings,
        "verifier_result": result,
        "verification_failed": failed,
        "report_status": "not_generated_verification_failed" if failed else "pending",
        "error": (
            "Report not generated because finding evidence references failed validation."
            if failed
            else state.get("error")
        ),
        "analyst_review_required": review_required,
        "review_reason": review_reason,
        "case_id": case_id,
    }
