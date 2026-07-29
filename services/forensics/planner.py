"""Agent-owned forensic tool planning over governed capability metadata."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.forensics.tools import artifact_profile, tool_status


PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "case_objective": {"type": "string"},
        "artifacts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_id": {"type": "string"},
                    "reasoning": {"type": "string"},
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool_id": {"type": "string"},
                                "objective": {"type": "string"},
                                "plugins": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": [
                                "tool_id", "objective", "plugins"
                            ],
                        },
                    },
                },
                "required": ["evidence_id", "reasoning", "tools"],
            },
        },
    },
    "required": ["case_objective", "artifacts"],
}


SYSTEM_PROMPT = """You are THOS's senior digital-forensics planning agent.
You own tool selection for each preserved artifact. Work from file facts,
chain-of-custody metadata, prior tool results, and the live governed tool
capability catalog.

Plan a complete but resource-conscious examination:
- identify format and metadata before choosing format-specific analyzers;
- use signature, string, structural, capability, document, registry, disk, or
  memory tools when their evidence can answer a stated objective;
- use Volatility plugins appropriate to the actual memory investigation rather
  than a fixed plugin list;
- use capa for supported static executables;
- select only tools present in the installed capability catalog;
- do not treat a tool match as a maliciousness verdict;
- never invent an artifact, tool, plugin, or prior result.

Return only schema-valid JSON. Every selected tool needs a concrete evidentiary
objective. An empty tool list is allowed only when no available capability can
examine that artifact, and the reasoning must explain the limitation."""


def _profiles(verified: dict) -> list[dict]:
    profiles = []
    for evidence in verified.get("evidence") or []:
        profiles.append({
            "evidence_id": str(evidence.get("evidence_id") or ""),
            "original_name": str(evidence.get("original_name") or ""),
            "sha256": str(evidence.get("sha256") or ""),
            **artifact_profile(
                evidence["path"],
                str(evidence.get("artifact_type") or "evidence"),
            ),
        })
    return profiles


async def plan_forensic_tools(
    verified: dict,
    prior_analysis: dict | None = None,
) -> dict:
    """Return a model-selected, capability-validated per-artifact tool plan."""
    status = tool_status()
    available = {
        str(item.get("tool_id")): item
        for item in status.get("tools") or []
        if item.get("status") in {"available", "degraded"}
    }
    evidence_ids = {
        str(item.get("evidence_id")) for item in verified.get("evidence") or []
    }
    already_executed: dict[str, set[str]] = {}
    if prior_analysis:
        for result in prior_analysis.get("static_analysis") or []:
            evidence_id = str(result.get("evidence_id") or "")
            already_executed.setdefault(evidence_id, set()).update(
                str(item.get("tool_id"))
                for item in result.get("results") or []
                if item.get("tool_id")
            )

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("artifacts must be a list")
        seen = set()
        normalized = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError("artifact plan was not an object")
            evidence_id = str(artifact.get("evidence_id") or "")
            if evidence_id not in evidence_ids or evidence_id in seen:
                raise ValueError(f"invalid or duplicate evidence_id {evidence_id}")
            seen.add(evidence_id)
            tools = []
            selected = set()
            for step in artifact.get("tools") or []:
                tool_id = str(step.get("tool_id") or "")
                if tool_id not in available:
                    raise ValueError(f"{tool_id} is not an available governed tool")
                if tool_id in selected or tool_id in already_executed.get(evidence_id, set()):
                    continue
                objective = str(step.get("objective") or "").strip()
                if not objective:
                    raise ValueError(f"{tool_id} has no evidentiary objective")
                plugins = [
                    str(plugin).strip()
                    for plugin in step.get("plugins") or []
                    if str(plugin).strip()
                ]
                if tool_id == "volatility3" and not plugins:
                    raise ValueError("Volatility was selected without agent-chosen plugins")
                if any(
                    not all(character.isalnum() or character in "._" for character in plugin)
                    for plugin in plugins
                ):
                    raise ValueError("Volatility plugin name was invalid")
                selected.add(tool_id)
                tools.append({
                    "tool_id": tool_id,
                    "objective": objective[:1000],
                    "parameters": {"plugins": plugins} if plugins else {},
                })
            normalized.append({
                "evidence_id": evidence_id,
                "reasoning": str(artifact.get("reasoning") or "")[:2000],
                "tools": tools,
            })
        missing = evidence_ids - seen
        if missing:
            raise ValueError(f"plan omitted evidence: {sorted(missing)}")
        return {
            "case_objective": str(payload.get("case_objective") or "")[:2000],
            "artifacts": normalized,
        }

    prompt = (
        "Chain-of-custody artifact facts:\n"
        f"{json.dumps(_profiles(verified), indent=2, default=str)}\n\n"
        "Live tool capabilities and availability:\n"
        f"{json.dumps(status, indent=2, default=str)}\n\n"
        "Prior tool results, if this is a follow-up planning pass:\n"
        f"{json.dumps(prior_analysis or {}, indent=2, default=str)[:50000]}"
    )
    try:
        return await decide_json(
            agent="forensic_planner",
            system=SYSTEM_PROMPT,
            prompt=prompt,
            schema=PLAN_SCHEMA,
            validator=validate,
        )
    except AgentDecisionError as exc:
        return {
            "case_objective": "Planner unavailable; no analytical tool was selected.",
            "artifacts": [
                {
                    "evidence_id": evidence_id,
                    "reasoning": str(exc),
                    "tools": [],
                }
                for evidence_id in sorted(evidence_ids)
            ],
            "_decision_metadata": {
                "owner": "forensic_planner_model",
                "degraded": True,
                "error": str(exc),
            },
        }
