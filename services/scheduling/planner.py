"""Agent-owned maintenance-window workload selection."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json


SCHEDULE_SCHEMA = {
    "type": "object",
    "properties": {
        "selected_target_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
        "rationale": {"type": "string"},
        "defer_reason": {"type": "string"},
    },
    "required": ["selected_target_ids", "rationale", "defer_reason"],
}


SYSTEM_PROMPT = """You are THOS's autonomous security-workload scheduler.
Select and order hypotheses that can run in the supplied maintenance window.

Use the actual evidence provided:
- prioritize materially overdue and never-run hypotheses while considering
  authored/agent-assigned severity, protected-asset relevance, previous
  failures, and observed duration;
- use per-hypothesis p95 duration when available and the supplied environment
  estimate otherwise;
- react to current model memory pressure, SIEM latency, queue depth, and recent
  failures without fixed catalog ordering;
- exploit related-source and ATT&CK overlap when it can reuse cached telemetry,
  but do not starve unrelated high-risk coverage;
- do not exceed the maintenance duration or maximum target count;
- return an empty list when current capacity makes safe execution unsuitable.

Return exact target IDs only and schema-valid JSON."""


async def select_scheduled_targets(
    *,
    targets: list[dict],
    durations: dict[str, dict],
    last_runs: dict[str, Any],
    target_history: dict[str, dict],
    capacity: dict[str, Any],
    maintenance_window_minutes: int,
    maximum_targets: int,
    default_duration_ms: int,
) -> tuple[list[dict], dict]:
    by_id = {
        str(target.get("id")): target
        for target in targets
        if target.get("id")
    }
    estimates = {
        target_id: max(
            1,
            int(
                (durations.get(target_id) or {}).get("p95_duration_ms")
                or (target_history.get(target_id) or {}).get("p95_duration_ms")
                or default_duration_ms
            ),
        )
        for target_id in by_id
    }
    window_ms = max(1, int(maintenance_window_minutes)) * 60_000
    maximum_targets = max(1, min(int(maximum_targets), len(by_id) or 1))

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        selected = [
            str(value) for value in payload.get("selected_target_ids") or []
        ]
        if len(selected) != len(set(selected)):
            raise ValueError("scheduler returned duplicate target IDs")
        if any(target_id not in by_id for target_id in selected):
            raise ValueError("scheduler returned an unknown target ID")
        if len(selected) > maximum_targets:
            raise ValueError("scheduler exceeded the maximum target count")
        predicted = sum(estimates[target_id] for target_id in selected)
        if predicted > window_ms:
            raise ValueError("scheduler exceeded the maintenance window")
        return {
            "selected_target_ids": selected,
            "rationale": str(payload.get("rationale") or "")[:4000],
            "defer_reason": str(payload.get("defer_reason") or "")[:4000],
            "predicted_p95_duration_ms": predicted,
        }

    prompt_targets = []
    for target_id, target in by_id.items():
        prompt_targets.append({
            "id": target_id,
            "title": target.get("title"),
            "severity": target.get("severity"),
            "tactic": target.get("hypothesis_tactic"),
            "technique": target.get("hypothesis_technique"),
            "last_completed_at": (
                (target_history.get(target_id) or {}).get("last_completed_at")
                or last_runs.get(target_id)
            ),
            "last_status": (
                target_history.get(target_id) or {}
            ).get("last_status"),
            "p50_duration_ms": (
                durations.get(target_id) or {}
            ).get("p50_duration_ms"),
            "p95_duration_ms": estimates[target_id],
        })
    try:
        decision = await decide_json(
            agent="schedule_planner",
            system=SYSTEM_PROMPT,
            prompt=json.dumps({
                "maintenance_window_minutes": maintenance_window_minutes,
                "maximum_targets": maximum_targets,
                "capacity": capacity,
                "targets": prompt_targets,
            }, indent=2, default=str)[:120000],
            schema=SCHEDULE_SCHEMA,
            validator=validate,
        )
        selected = [
            by_id[target_id]
            for target_id in decision["selected_target_ids"]
        ]
        return selected, {
            "maintenance_window_minutes": maintenance_window_minutes,
            "predicted_p95_duration_ms": decision[
                "predicted_p95_duration_ms"
            ],
            "adaptive_batch_size": len(selected),
            "capacity": capacity,
            "rationale": decision["rationale"],
            "defer_reason": decision["defer_reason"],
            "selection_owner": "schedule_planner_model",
        }
    except AgentDecisionError as exc:
        return [], {
            "maintenance_window_minutes": maintenance_window_minutes,
            "predicted_p95_duration_ms": 0,
            "adaptive_batch_size": 0,
            "capacity": capacity,
            "rationale": "",
            "defer_reason": str(exc),
            "selection_owner": "schedule_planner_model_unavailable",
        }
