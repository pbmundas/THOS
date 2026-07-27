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
_TOKEN = re.compile(r"[a-zA-Z0-9_.:-]{3,}")
_TOKEN_STOP = {"hard-evidence", "circumstantial", "evidence", "finding", "record", "ref", "with", "from", "that", "this"}


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


def _best_record_reference(line: str, logs: list[dict]) -> int | None:
    if not logs:
        return None
    terms = {token.lower() for token in _TOKEN.findall(line) if token.lower() not in _TOKEN_STOP}
    scores = []
    for index, log in enumerate(logs):
        haystack = " ".join(str(value) for key, value in log.items() if not str(key).startswith("_")).lower()
        scores.append((sum(1 for term in terms if term in haystack), index))
    return max(scores, key=lambda item: (item[0], -item[1]))[1]


def _repair_references(findings: str, logs: list[dict]) -> tuple[str, list[str]]:
    """Repair malformed/out-of-range citations without another model call.

    Numeric mistakes are clamped into the actual evidence range; malformed
    citations are re-grounded to the record with the largest literal token
    overlap. Repaired hard-evidence claims are downgraded to circumstantial and
    require analyst review, but they no longer abort report generation.
    """
    repaired: list[str] = []
    output = []
    for line in findings.splitlines():
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed
            value = match.group(1).strip()
            if value.lower() == "histogram":
                return match.group(0)
            numbers = _expand_references(value)
            if numbers is not None and all(0 <= number < len(logs) for number in numbers):
                return match.group(0)
            changed = True
            repaired.append(value)
            if not logs:
                replacement = "histogram"
            elif numbers:
                normalized = sorted({min(max(number, 0), len(logs) - 1) for number in numbers})
                replacement = ", ".join(str(number) for number in normalized)
            else:
                replacement = str(_best_record_reference(line, logs) or 0)
            return f"ref: {replacement}"

        line = _REF.sub(replace, line)
        if changed:
            line = line.replace("[hard-evidence]", "[circumstantial]")
        output.append(line)
    return "\n".join(output), repaired


async def verify_findings_node(state: HuntState) -> dict:
    findings = state.get("findings") or ""
    logs = state.get("processed_logs") or []
    log_count = len(logs)
    findings, repaired_refs = _repair_references(findings, logs)
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
    degraded = bool(state.get("reasoning_degraded"))
    result = {"status": "failed" if failed else "passed", "checked_citations": checked,
              "invalid_references": invalid_refs,
              "repaired_references": repaired_refs,
              "reason": "finding output had no verifiable citations" if no_citation else ("invalid record references" if invalid_refs else (f"repaired {len(repaired_refs)} invalid record reference(s) deterministically" if repaired_refs else "all cited references are in range"))}
    case_id = None
    review_required = failed or degraded or bool(repaired_refs)
    review_reason = (
        result["reason"] if failed
        else result["reason"] if repaired_refs
        else "Model-independent deterministic reasoning fallback was used after three model strikes"
    )
    if failed:
        findings += "\n\n- [circumstantial] Verifier warning: one or more finding citations could not be validated; analyst review is required."
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
        "analyst_review_required": review_required,
        "review_reason": review_reason if review_required else None,
        "case_id": case_id,
    }
