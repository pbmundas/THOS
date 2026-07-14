"""Draft a conservative Sigma proposal; never writes into the live ruleset."""
import re
from services.orchestration.state import HuntState


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:60] or "thos_hunt_proposal"


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
    return {"proposed_detection_rule": "\n".join(lines) + "\n"}
