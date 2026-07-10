from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState


async def select_hypothesis(state: HuntState) -> dict:
    """
    If the hunter already specified a hypothesis_id, fetch its detail.
    Otherwise, if hunter_name / a free-text intent is given via
    hypothesis_text, run a semantic search to suggest one.
    """
    if state.get("hypothesis_id"):
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
        "hypothesis_text": detail.get("text", state.get("hypothesis_text", "")),
        "technique_id": technique_id,
        "technique_name": mitre_detail.get("name", ""),
        "tactic": detail.get("tactic", mitre_detail.get("tactic", "")),
    }
