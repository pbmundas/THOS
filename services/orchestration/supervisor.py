"""Structured model-driven planning with bounded evidence-based replanning."""
from __future__ import annotations

import json
import logging

from services.orchestration.state import HuntState
from services.reasoning.ollama_client import generate

logger = logging.getLogger(__name__)
ALLOWED_NODES = {
    "query_gen", "siem_fetch", "log_processing", "guardrail", "soc_tools",
    "coverage_gap", "adaptive_replan", "threat_intel", "reasoning", "verifier",
    "detection_engineering", "communication", "report",
}
REQUIRED_ORDER = [
    "query_gen", "siem_fetch", "log_processing", "guardrail", "soc_tools",
    "coverage_gap", "adaptive_replan", "threat_intel", "reasoning", "verifier",
    "detection_engineering", "communication", "report",
]
PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "plan": {
            "type": "array",
            "items": {"type": "string", "enum": sorted(ALLOWED_NODES)},
            "minItems": 6,
            "maxItems": 12,
        },
        "rationale": {"type": "string"},
        "risk_focus": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
    },
    "required": ["plan", "rationale", "risk_focus"],
}
REPLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["continue", "refine_query"]},
        "follow_up_query": {"type": "string"},
        "reason": {"type": "string"},
    },
    "required": ["action", "follow_up_query", "reason"],
}
SYSTEM = """You are THOS's read-only threat-hunt planning supervisor. Produce a
bounded plan from the allowed nodes. Never omit guardrail, coverage, reasoning,
verification, communication, or report. You may order only according to the
normal evidence flow. Do not request containment, deletion, configuration
changes, or any tool outside the schema. Return only valid JSON."""
REPLAN_SYSTEM = """You are THOS's bounded replanning supervisor. Decide whether
one additional read-only query is justified by intermediate telemetry. Refine
only when the current query returned weak or clearly incomplete evidence and a
new query could retrieve different records from the same configured source.
Missing telemetry sources cannot be fixed by repeating a query. Never repeat the
current query. Return only valid JSON."""


def _fallback_plan(state: HuntState) -> list[str]:
    return list(REQUIRED_ORDER)


def _normalize_plan(value) -> list[str]:
    requested = [str(item) for item in (value or []) if str(item) in ALLOWED_NODES]
    # The graph enforces this safe evidence order. Model selection remains
    # visible as intent, while mandatory safety stages can never be removed.
    return [node for node in REQUIRED_ORDER if node in requested or node in {
        "query_gen", "siem_fetch", "log_processing", "guardrail", "soc_tools",
        "coverage_gap", "adaptive_replan", "threat_intel", "reasoning",
        "verifier", "communication", "report",
    }]


async def plan_hunt_node(state: HuntState) -> dict:
    prompt = json.dumps({
        "hypothesis": state.get("hypothesis_text", ""),
        "technique_id": state.get("technique_id", ""),
        "tactic": state.get("tactic", ""),
        "telemetry_source": state.get("siem_type", ""),
        "prior_hunt_count": len(state.get("hunt_memory") or []),
        "allowed_nodes": sorted(ALLOWED_NODES),
    }, ensure_ascii=False)
    try:
        raw = await generate(
            prompt, system=SYSTEM, format=PLAN_SCHEMA,
            agent="supervisor", transport_retries=1,
        )
        parsed = json.loads(raw)
        plan = _normalize_plan(parsed.get("plan"))
        if not plan:
            raise ValueError("planner returned no valid nodes")
        return {
            "plan": plan,
            "plan_rationale": str(parsed.get("rationale") or ""),
            "plan_risk_focus": [str(item) for item in parsed.get("risk_focus", [])[:6]],
            "planner_mode": "model",
        }
    except Exception as exc:  # noqa: BLE001 - safe deterministic fallback
        logger.warning("supervisor model plan failed; using deterministic safety plan: %s", exc)
        return {
            "plan": _fallback_plan(state),
            "plan_rationale": f"Deterministic safety plan used because model planning failed: {exc}",
            "plan_risk_focus": [],
            "planner_mode": "deterministic_fallback",
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
