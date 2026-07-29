"""Truthful deterministic planning with bounded evidence-based replanning."""
from __future__ import annotations

import json
import logging

from services.orchestration.state import HuntState
from services.reasoning.ollama_client import generate

logger = logging.getLogger(__name__)
ALLOWED_NODES = {
    "query_gen", "siem_fetch", "log_processing", "guardrail", "soc_tools",
    "coverage_gap", "threat_intel", "negative_screening_gate",
    "adaptive_replan", "reasoning", "verifier", "detection_engineering",
    "communication", "report",
}
REQUIRED_ORDER = [
    "query_gen", "siem_fetch", "log_processing", "guardrail", "soc_tools",
    "coverage_gap", "threat_intel", "negative_screening_gate",
    "adaptive_replan", "reasoning", "verifier", "detection_engineering",
    "communication", "report",
]
REPLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["continue", "refine_query"]},
        "follow_up_query": {"type": "string"},
        "reason": {"type": "string"},
    },
    "required": ["action", "follow_up_query", "reason"],
}
REPLAN_SYSTEM = """You are THOS's bounded replanning supervisor. Decide whether
one additional read-only query is justified by intermediate telemetry. Refine
only when the current query returned weak or clearly incomplete evidence and a
new query could retrieve different records from the same configured source.
Missing telemetry sources cannot be fixed by repeating a query. Never repeat the
current query. Return only valid JSON."""


def _fallback_plan(state: HuntState) -> list[str]:
    return list(REQUIRED_ORDER)


async def plan_hunt_node(state: HuntState) -> dict:
    # LangGraph executes a governed, fixed safety order; a model-generated plan
    # could not change that order and therefore consumed inference time without
    # affecting execution. Report the actual graph plan directly.
    return {
        "plan": _fallback_plan(state),
        "plan_rationale": (
            "Governed read-only evidence flow for "
            f"{state.get('siem_type') or 'the configured telemetry source'}; "
            "empty evidence exits before adaptive or reasoning model work."
        ),
        "plan_risk_focus": [],
        "planner_mode": "deterministic_graph",
    }


async def adaptive_replan_node(state: HuntState) -> dict:
    prior = int(state.get("adaptive_replans") or 0)
    if prior >= int(state.get("max_adaptive_replans") or 1):
        return {"replan_action": "continue"}
    prompt = json.dumps({
        "hypothesis": state.get("hypothesis_text", ""),
        "technique_id": state.get("technique_id", ""),
        "telemetry_source": state.get("siem_type", ""),
        "current_query": state.get("query", ""),
        "executed_queries": state.get("executed_queries") or [],
        "record_count": len(state.get("processed_logs") or []),
        "telemetry_profile": state.get("telemetry_profile") or {},
        "coverage_assessment": state.get("coverage_assessment") or {},
        "sigma_matched_count": state.get("sigma_matched_count", 0),
        "guardrail_status": (state.get("guardrail_result") or {}).get("status"),
    }, ensure_ascii=False, default=str)
    try:
        raw = await generate(
            prompt, system=REPLAN_SYSTEM, format=REPLAN_SCHEMA,
            agent="supervisor", transport_retries=1,
        )
        parsed = json.loads(raw)
        action = str(parsed.get("action") or "continue")
        follow_up = str(parsed.get("follow_up_query") or "").strip()
        executed = set(state.get("executed_queries") or [])
        if action != "refine_query" or not follow_up or follow_up in executed:
            action, follow_up = "continue", ""
        history = list(state.get("replan_history") or [])
        history.append({
            "sequence": prior + 1,
            "action": action,
            "reason": str(parsed.get("reason") or ""),
            "follow_up_query": follow_up,
        })
        return {
            "replan_action": action,
            "follow_up_query": follow_up or None,
            "need_more_logs": action == "refine_query",
            "adaptive_replans": prior + (1 if action == "refine_query" else 0),
            "replan_history": history,
        }
    except Exception as exc:  # fail safely and continue the current hunt
        logger.warning("adaptive replanning failed; continuing current plan: %s", exc)
        return {
            "replan_action": "continue",
            "replan_history": [
                *(state.get("replan_history") or []),
                {"sequence": prior + 1, "action": "continue", "reason": f"planner unavailable: {exc}"},
            ],
        }
