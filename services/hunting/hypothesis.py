import re

from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState


_LITERAL_OBSERVABLES = re.compile(
    r"""(?ix)
    \b(?:
        [a-z0-9_.-]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|msi|sh)
        |
        (?:event\s*id|eventid)[\s:_-]*\d{1,6}
        |
        (?:tcp|udp)?\s*port\s+\d{1,5}
        |
        T\d{4}(?:\.\d{3})?
    )\b
    """
)


def _investigation_requirements(detail: dict, mitre_detail: dict) -> dict:
    """Preserve a verifiable hunt contract instead of passing only prose."""
    text = str(detail.get("text") or "")
    observables = list(dict.fromkeys(
        match.group(0).strip()
        for match in _LITERAL_OBSERVABLES.finditer(text)
    ))[:30]
    return {
        "title": str(detail.get("title") or "")[:500],
        "statement": text,
        "technique_id": str(detail.get("technique") or ""),
        "tactic": str(detail.get("tactic") or mitre_detail.get("tactic") or ""),
        "required_data_sources": list(mitre_detail.get("data_sources") or []),
        "literal_observables": observables,
        "investigation_steps": [
            "Validate that each required telemetry category is available in the selected source set.",
            "Run a high-precision direct-evidence query using only literal hypothesis and governed ATT&CK context.",
            "If the search is empty, expand the bounded time window and run a broader technique/context query.",
            "If the search is noisy or capped, tighten on observed entities, event categories, and adjacent timestamps.",
            "Correlate supported leads by host, user, process, network entity, and time across selected sources.",
            "Conclude only after planned retrieval branches are executed or explicitly recorded as unavailable.",
        ],
        "completion_criteria": (
            "Every selected telemetry source was queried, required ATT&CK data-source "
            "coverage was assessed, query failures were recorded, and supported leads "
            "were correlated or the evidence gate stopped model reasoning."
        ),
    }


async def select_hypothesis(state: HuntState) -> dict:
    """
    If the hunter already specified a hypothesis_id, fetch its detail.
    Otherwise, if hunter_name / a free-text intent is given via
    hypothesis_text, run a semantic search to suggest one.
    """
    if state.get("hypothesis_id") and state.get("hypothesis_text"):
        detail = {
            "id": state["hypothesis_id"],
            "text": state["hypothesis_text"],
            "tactic": state.get("hypothesis_tactic", ""),
            "technique": state.get("hypothesis_technique", ""),
        }
    elif state.get("hypothesis_id"):
        detail = await call_tool("get_hearth_hypothesis", {"hypothesis_id": state["hypothesis_id"]})
    else:
        candidates = await call_tool(
            "search_hypotheses_semantic",
            {"query": state.get("hypothesis_text", ""), "n_results": 1},
        )
        if candidates:
            detail = candidates[0].get("meta", {})
        else:
            all_h = await call_tool("list_hearth_hypotheses", {"tactic": ""})
            detail = all_h[0] if all_h else {}

    technique_id = detail.get("technique")
    mitre_detail = {}
    if technique_id:
        mitre_detail = await call_tool("mitre_map_technique", {"technique_id": technique_id})

    return {
        "hypothesis_id": detail.get("id", state.get("hypothesis_id")),
        "hypothesis_title": detail.get("title", ""),
        "hypothesis_text": detail.get("text", state.get("hypothesis_text", "")),
        "technique_id": technique_id,
        "technique_name": mitre_detail.get("name", ""),
        "tactic": detail.get("tactic", mitre_detail.get("tactic", "")),
        "hypothesis_severity": detail.get("severity", ""),
        "hypothesis_category": detail.get("category", ""),
        "investigation_requirements": _investigation_requirements(detail, mitre_detail),
    }
