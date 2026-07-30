from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState


async def generate_query_node(state: HuntState) -> dict:
    configured = [
        str(source).strip().lower()
        for source in (
            state.get("source_priority")
            or state.get("siem_types")
            or [state.get("siem_type", "folder")]
        )
        if str(source).strip()
    ]
    sources = list(dict.fromkeys(configured)) or ["folder"]
    primary = str(
        state.get("active_query_source")
        or state.get("siem_type")
        or sources[0]
    ).strip().lower()
    if primary not in sources:
        sources.insert(0, primary)
    else:
        sources = [primary, *[source for source in sources if source != primary]]
    objective = str(state.get("active_query_objective") or "").strip()
    if not objective:
        raise ValueError(
            "Supervisor Agent did not provide an initial investigation objective"
        )
    context = {
        "technique_id": state.get("technique_id", ""),
        "technique_name": state.get("technique_name", ""),
        "tactic": state.get("tactic", ""),
        "requirements": state.get("investigation_requirements") or {},
        "phase": "supervisor_initial_plan",
        "supervisor_rationale": state.get("plan_rationale", ""),
        "risk_focus": state.get("plan_risk_focus") or [],
    }
    result = await call_tool(
        "generate_siem_query",
        {
            "hypothesis_text": state.get("hypothesis_text", ""),
            "siem_type": primary,
            "objective": objective,
            "investigation_context": context,
        },
    )
    primary_step = {
        "sequence": 1,
        "source": primary,
        "objective": objective,
        "phase": "primary",
        "query": result.get("query", ""),
        "status": "ready" if result.get("query") else "query_generation_failed",
    }
    pending = [
        {
            "sequence": index + 2,
            "source": source,
            "objective": objective,
            "phase": "primary",
            "query": "",
            "status": "pending_generation",
        }
        for index, source in enumerate(sources[1:])
    ]
    return {
        "siem_types": sources,
        "active_query_source": primary,
        "active_query": result.get("query", ""),
        "active_query_objective": objective,
        "query": result.get("query", ""),
        "query_plan": [primary_step, *pending],
        "pending_query_plan": pending,
        "query_used_fallback": result.get("query_used_fallback", False),
        "query_validation_error": result.get("query_validation_error"),
        "query_generation_mode": result.get(
            "query_generation_mode",
            "model",
        ),
        "query_generation_warnings": result.get(
            "query_generation_warnings",
            [],
        ),
    }
