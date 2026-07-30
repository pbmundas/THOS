"""Agent-owned threat-hunt planning and adaptive retrieval supervision."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.hunting.evidence_selector import _model_record
from services.hunting.query_generator import validate_and_normalize_query
from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState
from services.runtime_config import get_value


# This is the governed evidence pipeline, not an investigative conclusion.
REQUIRED_ORDER = [
    "query_gen",
    "siem_fetch",
    "log_processing",
    "guardrail",
    "soc_tools",
    "coverage_gap",
    "threat_intel",
    "adaptive_replan",
    "negative_screening_gate",
    "reasoning",
    "verifier",
    "detection_engineering",
    "communication",
    "report",
]

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string", "maxLength": 1200},
        "risk_focus": {
            "type": "array",
            "items": {"type": "string", "maxLength": 300},
            "maxItems": 8,
        },
        "initial_objective": {"type": "string", "maxLength": 1200},
        "source_priority": {
            "type": "array",
            "items": {"type": "string"},
        },
        "lookback_minutes": {"type": "integer"},
        "limit": {"type": "integer"},
    },
    "required": [
        "rationale",
        "risk_focus",
        "initial_objective",
        "source_priority",
        "lookback_minutes",
        "limit",
    ],
}

REPLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["continue", "refine_query"]},
        "objective": {"type": "string"},
        "source": {"type": "string"},
        "lookback_minutes": {"type": "integer"},
        "limit": {"type": "integer"},
        "reason": {"type": "string"},
    },
    "required": [
        "action",
        "objective",
        "source",
        "lookback_minutes",
        "limit",
        "reason",
    ],
}

PLAN_SYSTEM = """You are THOS's senior threat-hunt planning agent. Build the
initial evidence-retrieval strategy for the supplied hypothesis, selected
telemetry sources, source schemas/capabilities, ATT&CK context, and prior hunt
memory.

Follow an experienced hunter process:
- decompose the hypothesis into behavioral, artifact, identity, process,
  network, persistence, and temporal evidence branches that actually apply;
- prioritize the source most likely to answer the first branch, but include
  every user-selected source in source_priority exactly once;
- choose a bounded lookback and result limit appropriate to the hypothesis,
  source capability, expected event density, and available resource bounds;
- state an initial objective that tells the Query Generation Agent what
  evidence to retrieve, not a raw query;
- keep the rationale to three concise sentences;
- keep lookback and result limits only in their dedicated numeric fields, not
  in initial_objective;
- do not invent observables or assume that an ATT&CK mapping proves activity.

Return only schema-valid JSON."""


def _decision_token_budget() -> int:
    return max(128, min(
        2048,
        int(get_value(
            "autonomy",
            "supervisor_decision_num_predict",
            default=512,
        )),
    ))

REPLAN_SYSTEM = """You are THOS's senior adaptive threat-hunt supervisor. You
alone decide whether the investigation needs another retrieval step or can
continue to the evidence gate and reasoning.

Review every prior query, result count, source diagnostic, telemetry profile,
coverage assessment, observed entity, evidence fact, IOC match, and remaining
resource budget. An experienced hunt may:
- broaden or restructure an empty or over-constrained query;
- tighten a noisy/capped query around literal observed entities or a distinct
  evidence branch;
- expand or shift the bounded time window;
- pivot by host, user, process, network entity, parent/child activity, or
  adjacent authentication/file/network events when those pivots are grounded;
- query a different user-selected source when it can answer a missing branch;
- stop retrieval when meaningful branches are exhausted, sources are
  unavailable, or further retrieval would repeat existing evidence.

Do not write a raw query. Select a source, objective, lookback, and limit; the
Query Generation Agent creates the source dialect. Do not repeat an equivalent
retrieval step. Do not continue while a user-selected source has never been
queried or documented unavailable. Return only schema-valid JSON."""


def _selected_sources(state: HuntState) -> list[str]:
    return list(dict.fromkeys(
        str(source).strip().lower()
        for source in (
            state.get("siem_types")
            or [state.get("siem_type") or "folder"]
        )
        if str(source).strip()
    ))


def _compact_context_items(
    items,
    *,
    item_cap: int | None = None,
    char_cap: int | None = None,
) -> list:
    """Bound model context while keeping the authoritative hunt state intact."""
    maximum_items = max(1, int(item_cap or get_value(
        "autonomy", "supervisor_context_item_cap", default=8
    )))
    maximum_chars = max(400, int(char_cap or get_value(
        "autonomy", "supervisor_context_char_cap", default=1400
    )))
    return [
        _model_record(item, maximum_chars)
        if isinstance(item, dict)
        else str(item)[:maximum_chars]
        for item in list(items or [])[:maximum_items]
    ]


def _compact_hunt_memory(items) -> list[dict[str, Any]]:
    """Project prior hunts to decision-relevant conclusions, never raw telemetry."""
    fields = (
        "hunt_id",
        "hypothesis_id",
        "hypothesis_text",
        "technique_id",
        "technique_name",
        "summary",
        "reasoning_summary",
        "findings",
        "recommendations",
        "status",
        "completed_at",
        "similarity",
    )
    projected = [
        {
            field: item[field]
            for field in fields
            if isinstance(item, dict)
            and item.get(field) not in (None, "", [], {})
        }
        for item in list(items or [])
        if isinstance(item, dict)
    ]
    return _compact_context_items(
        projected,
        item_cap=int(get_value(
            "autonomy",
            "supervisor_memory_item_cap",
            default=4,
        )),
    )


def _observed_entities(
    state: HuntState,
    per_type: int = 20,
) -> dict[str, list[str]]:
    """Return literal normalized values as model context, not decisions."""
    fields = {
        "hosts": ("host", "hostname", "computer_name", "agent_name"),
        "users": ("user", "username", "account_name", "subject_user"),
        "source_ips": ("src_ip", "source_ip"),
        "destination_ips": ("dst_ip", "destination_ip"),
        "processes": ("process", "process_name", "image", "command"),
        "events": ("event", "event_id", "rule_id"),
    }
    observed = {name: [] for name in fields}
    for record in state.get("processed_logs") or []:
        if not isinstance(record, dict):
            continue
        raw = record.get("_raw") if isinstance(record.get("_raw"), dict) else {}
        for category, candidates in fields.items():
            if len(observed[category]) >= per_type:
                continue
            for field in candidates:
                value = record.get(field)
                if value in (None, ""):
                    value = raw.get(field)
                text = str(value or "").strip()
                if text and len(text) <= 500 and text not in observed[category]:
                    observed[category].append(text)
                    break
    return {name: values for name, values in observed.items() if values}


def _completion(state: HuntState, exhausted: bool) -> dict:
    selected = _selected_sources(state)
    diagnostics = state.get("source_diagnostics") or {}
    queried = [
        source
        for source in selected
        if (diagnostics.get(source) or {}).get("status")
        in {"queried", "unavailable", "query_generation_failed"}
    ]
    unavailable = [
        source
        for source in selected
        if (diagnostics.get(source) or {}).get("status")
        in {"unavailable", "query_generation_failed"}
    ]
    capped = []
    for source in selected:
        diagnostic = diagnostics.get(source) or {}
        total = diagnostic.get("last_total_hits")
        count = diagnostic.get("last_record_count")
        try:
            if total is not None and int(total) > int(count or 0):
                capped.append(source)
        except (TypeError, ValueError):
            pass
    return {
        "status": (
            "complete_with_source_gaps"
            if exhausted and unavailable
            else "complete_with_result_caps"
            if exhausted and capped
            else "complete"
            if exhausted and len(queried) == len(selected)
            else "incomplete"
        ),
        "retrieval_exhausted": exhausted,
        "selected_sources": selected,
        "queried_sources": queried,
        "unavailable_sources": unavailable,
        "capped_sources": capped,
        "attempt_count": len(state.get("retrieval_attempts") or []),
        "coverage_status": (
            state.get("coverage_assessment") or {}
        ).get("status", "unknown"),
    }


def _history(
    state: HuntState,
    *,
    action: str,
    reason: str,
    source: str = "",
    objective: str = "",
    query: str = "",
    lookback_minutes: int | None = None,
    limit: int | None = None,
    owner: str = "supervisor_model",
) -> list[dict]:
    history = list(state.get("replan_history") or [])
    history.append({
        "sequence": len(history) + 1,
        "action": action,
        "reason": reason,
        "source": source,
        "objective": objective,
        "follow_up_query": query,
        "lookback_minutes": lookback_minutes,
        "limit": limit,
        "decision_owner": owner,
    })
    return history


async def _generate_step_query(
    state: HuntState,
    source: str,
    objective: str,
    context: dict,
) -> tuple[str, dict]:
    result = await call_tool("generate_siem_query", {
        "hypothesis_text": state.get("hypothesis_text", ""),
        "siem_type": source,
        "objective": objective,
        "investigation_context": context,
    })
    validation = validate_and_normalize_query(
        str(result.get("query") or ""),
        state.get("hypothesis_text", "") or "",
        source,
    )
    return validation["query"], {
        **validation,
        "generator_validation_error": result.get("query_validation_error"),
    }


async def plan_hunt_node(state: HuntState) -> dict:
    sources = _selected_sources(state)
    max_lookback = max(1, int(state.get("max_lookback_minutes") or 10080))
    max_limit = max(1, int(state.get("max_query_limit") or 2000))
    plan_schema = {
        **PLAN_SCHEMA,
        "properties": {
            **PLAN_SCHEMA["properties"],
            "source_priority": {
                "type": "array",
                "items": {"type": "string", "enum": sources},
                "minItems": len(sources),
                "maxItems": len(sources),
                "uniqueItems": True,
            },
        },
    }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        source_priority = [
            str(value).lower() for value in payload.get("source_priority") or []
        ]
        if (
            len(source_priority) != len(sources)
            or set(source_priority) != set(sources)
        ):
            raise ValueError("source_priority did not contain every selected source")
        lookback = int(payload.get("lookback_minutes"))
        limit = int(payload.get("limit"))
        if not 1 <= lookback <= max_lookback:
            raise ValueError("lookback exceeded the governed bound")
        if not 1 <= limit <= max_limit:
            raise ValueError("result limit exceeded the governed bound")
        objective = str(payload.get("initial_objective") or "").strip()
        if not objective:
            raise ValueError("initial objective was empty")
        return {
            "rationale": str(payload.get("rationale") or "")[:4000],
            "risk_focus": [
                str(value)[:1000] for value in payload.get("risk_focus") or []
            ],
            "initial_objective": objective[:4000],
            "source_priority": source_priority,
            "lookback_minutes": lookback,
            "limit": limit,
        }

    decision = await decide_json(
        agent="supervisor",
        system=PLAN_SYSTEM,
        prompt=json.dumps({
            "hypothesis": state.get("hypothesis_text"),
            "hypothesis_title": state.get("hypothesis_title"),
            "technique_id": state.get("technique_id"),
            "technique_name": state.get("technique_name"),
            "tactic": state.get("tactic"),
            "investigation_requirements": (
                state.get("investigation_requirements") or {}
            ),
            "selected_sources": sources,
            "hunt_memory": _compact_hunt_memory(
                state.get("hunt_memory") or []
            ),
            "resource_bounds": {
                "max_lookback_minutes": max_lookback,
                "max_query_limit": max_limit,
            },
        }, ensure_ascii=False, separators=(",", ":"), default=str),
        schema=plan_schema,
        validator=validate,
        num_predict=_decision_token_budget(),
    )
    return {
        "plan": list(REQUIRED_ORDER),
        "plan_rationale": decision["rationale"],
        "plan_risk_focus": decision["risk_focus"],
        "planner_mode": "supervisor_model",
        "source_priority": decision["source_priority"],
        "siem_type": decision["source_priority"][0],
        "active_query_source": decision["source_priority"][0],
        "active_query_objective": decision["initial_objective"],
        "active_lookback_minutes": decision["lookback_minutes"],
        "active_query_limit": decision["limit"],
    }


async def adaptive_replan_node(state: HuntState) -> dict:
    prior = int(state.get("adaptive_replans") or 0)
    maximum = int(state.get("max_adaptive_replans") or 0)
    if prior >= maximum:
        reason = (
            f"Governed adaptive retrieval ceiling reached after {prior} "
            "model-directed refinement(s)."
        )
        return {
            "replan_action": "continue",
            "replan_decision_owner": "resource_guardrail",
            "retrieval_exhausted": True,
            "hunt_completeness": _completion(state, True),
            "replan_history": _history(
                state,
                action="continue",
                reason=reason,
                owner="resource_guardrail",
            ),
        }
    sources = _selected_sources(state)
    max_lookback = max(1, int(state.get("max_lookback_minutes") or 10080))
    max_limit = max(1, int(state.get("max_query_limit") or 2000))
    diagnostics = state.get("source_diagnostics") or {}
    coverage_rows = (
        (state.get("coverage_assessment") or {}).get("data_sources") or []
    )
    uncovered_data_sources = list(dict.fromkeys(
        str(row.get("data_source") or "").strip()
        for row in coverage_rows
        if isinstance(row, dict)
        and row.get("status") != "covered"
        and str(row.get("data_source") or "").strip()
    ))
    if not uncovered_data_sources:
        uncovered_data_sources = list(dict.fromkeys(
            str(source).strip()
            for source in (
                (state.get("investigation_requirements") or {}).get(
                    "required_data_sources"
                )
                or []
            )
            if str(source).strip()
        ))
    unqueried = [
        source
        for source in sources
        if (diagnostics.get(source) or {}).get("status")
        not in {"queried", "unavailable", "query_generation_failed"}
    ]

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action") or "")
        source = str(payload.get("source") or "").lower()
        if source not in sources:
            raise ValueError("supervisor selected a source outside user scope")
        if action == "continue" and unqueried:
            raise ValueError(
                f"selected sources remain unqueried: {unqueried}"
            )
        lookback = int(payload.get("lookback_minutes"))
        limit = int(payload.get("limit"))
        if not 1 <= lookback <= max_lookback:
            raise ValueError("lookback exceeded the governed bound")
        if not 1 <= limit <= max_limit:
            raise ValueError("result limit exceeded the governed bound")
        objective = str(payload.get("objective") or "").strip()
        reason = str(payload.get("reason") or "").strip()
        if not objective or not reason:
            raise ValueError("supervisor omitted objective or reason")
        return {
            "action": action,
            "source": source,
            "lookback_minutes": lookback,
            "limit": limit,
            "objective": objective[:4000],
            "reason": reason[:4000],
        }

    context = {
        "hypothesis": state.get("hypothesis_text"),
        "technique": {
            "id": state.get("technique_id"),
            "name": state.get("technique_name"),
        },
        "selected_sources": sources,
        "unqueried_sources": unqueried,
        "source_diagnostics": diagnostics,
        "retrieval_attempts": _compact_context_items(
            state.get("retrieval_attempts") or []
        ),
        "telemetry_profile": state.get("telemetry_profile") or {},
        "coverage_assessment": state.get("coverage_assessment") or {},
        "coverage_gaps": state.get("coverage_gaps") or [],
        "required_data_sources": uncovered_data_sources,
        "evidence_counts": {
            "detection_rule_matches": int(
                state.get("sigma_matched_count") or 0
            ),
            "artifact_highlights": len(
                state.get("evidence_highlights") or []
            ),
            "behavioral_matches": len(
                state.get("behavioral_evidence") or []
            ),
            "ioc_matches": len(state.get("enrichment_hits") or []),
        },
        "observed_entities": _observed_entities(state),
        "prior_supervisor_decisions": _compact_context_items(
            state.get("replan_history") or []
        ),
        "resource_bounds": {
            "remaining_refinements": maximum - prior,
            "max_lookback_minutes": max_lookback,
            "max_query_limit": max_limit,
        },
    }
    try:
        decision = await decide_json(
            agent="supervisor",
            system=REPLAN_SYSTEM,
            prompt=json.dumps(context, indent=2, default=str)[:120000],
            schema=REPLAN_SCHEMA,
            validator=validate,
            num_predict=_decision_token_budget(),
        )
    except AgentDecisionError as exc:
        return {
            "replan_action": "continue",
            "replan_decision_owner": "supervisor_model_unavailable",
            "retrieval_exhausted": False,
            "hunt_completeness": _completion(state, False),
            "coverage_gaps": list(dict.fromkeys([
                *(state.get("coverage_gaps") or []),
                f"Adaptive Supervisor Agent failed: {exc}",
            ])),
            "replan_history": _history(
                state,
                action="continue",
                reason=str(exc),
                owner="supervisor_model_unavailable",
            ),
        }
    if decision["action"] == "continue":
        return {
            "replan_action": "continue",
            "replan_decision_owner": "supervisor_model",
            "retrieval_exhausted": True,
            "hunt_completeness": _completion(state, True),
            "replan_history": _history(
                state,
                action="continue",
                reason=decision["reason"],
            ),
        }
    query, validation = await _generate_step_query(
        state,
        decision["source"],
        decision["objective"],
        context,
    )
    if not query:
        return {
            "replan_action": "continue",
            "replan_decision_owner": "query_generation_failed",
            "retrieval_exhausted": False,
            "hunt_completeness": _completion(state, False),
            "coverage_gaps": list(dict.fromkeys([
                *(state.get("coverage_gaps") or []),
                (
                    "Query Generation Agent could not implement the Supervisor "
                    f"Agent decision: {validation.get('validation_error') or validation.get('generator_validation_error')}"
                ),
            ])),
            "replan_history": _history(
                state,
                action="continue",
                reason=(
                    "Supervisor requested a refinement, but no validated query "
                    "was generated."
                ),
                owner="query_generation_failed",
            ),
        }
    return {
        "replan_action": "refine_query",
        "follow_up_query": query,
        "follow_up_source": decision["source"],
        "follow_up_lookback_minutes": decision["lookback_minutes"],
        "follow_up_limit": decision["limit"],
        "follow_up_objective": decision["objective"],
        "need_more_logs": True,
        "replan_decision_owner": "supervisor_model",
        "adaptive_replans": prior + 1,
        "retrieval_exhausted": False,
        "hunt_completeness": _completion(state, False),
        "replan_history": _history(
            state,
            action="refine_query",
            reason=decision["reason"],
            source=decision["source"],
            objective=decision["objective"],
            query=query,
            lookback_minutes=decision["lookback_minutes"],
            limit=decision["limit"],
        ),
    }
