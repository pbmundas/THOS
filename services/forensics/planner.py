"""Agent-owned forensic tool planning over governed capability metadata."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.forensics.tools import artifact_profile, tool_status
from services.runtime_config import get_value


PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "case_objective": {"type": "string"},
        "analysis_strategy": {
            "type": "string",
            "enum": ["rapid", "balanced", "deep"],
        },
        "artifacts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_id": {"type": "string"},
                    "reasoning": {"type": "string"},
                    "required_capabilities": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "deferred_tools": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool_id": {"type": "string"},
                                "reason": {"type": "string"},
                            },
                            "required": ["tool_id", "reason"],
                        },
                    },
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
                "required": [
                    "evidence_id", "reasoning", "required_capabilities",
                    "deferred_tools", "tools"
                ],
            },
        },
    },
    "required": ["case_objective", "analysis_strategy", "artifacts"],
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
- declare every material capability required to answer the artifact's
  evidentiary questions, then cover each declared capability with a selected
  tool; explicitly defer remaining applicable tools with a reason;
- select independent complementary tools together because THOS can execute
  read-only adapters concurrently;
- use rapid for cheap identification/triage, balanced for normal cases, and
  deep only when artifact facts or prior observations justify expensive work;
- do not treat a tool match as a maliciousness verdict;
- never invent an artifact, tool, plugin, or prior result.

Return only schema-valid JSON. Every selected tool needs a concrete evidentiary
objective. The initial pass must select at least one installed tool for every
artifact when tools are available. A follow-up pass may be empty when the prior
results answer the material questions."""


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


def _compact_prior_analysis(prior: dict | None) -> dict:
    if not prior:
        return {}
    result_cap = max(
        1, int(get_value("forensics", "planner_prior_result_cap", default=40))
    )
    char_cap = max(
        200, int(get_value("forensics", "planner_prior_char_cap", default=1200))
    )
    results = []
    for artifact in prior.get("static_analysis") or []:
        for item in artifact.get("results") or []:
            if not isinstance(item, dict):
                continue
            results.append({
                "evidence_id": artifact.get("evidence_id"),
                "tool_id": item.get("tool_id"),
                "status": item.get("status"),
                "duration_ms": item.get("duration_ms"),
                "exit_code": item.get("exit_code"),
                "data": str(item.get("data") or "")[:char_cap],
                "output": str(item.get("output") or "")[:char_cap],
                "error": str(item.get("error") or "")[:400],
                "note": str(item.get("note") or "")[:400],
            })
            if len(results) >= result_cap:
                break
        if len(results) >= result_cap:
            break
    return {
        "tool_results": results,
        "warnings": list(prior.get("warnings") or [])[:20],
        "record_count": len(prior.get("records") or []),
        "archive_count": len(prior.get("archives") or []),
        "disk_image_count": len(prior.get("disk_images") or []),
        "omitted_tool_results": max(
            0,
            sum(
                len(item.get("results") or [])
                for item in prior.get("static_analysis") or []
            ) - len(results),
        ),
    }


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
    capability_names = {
        str(capability)
        for item in available.values()
        for capability in item.get("capabilities") or []
    }
    phase = "followup" if prior_analysis else "initial"
    max_tools = max(
        1,
        min(
            int(get_value(
                "forensics", "planner_max_tools_per_artifact", default=8
            )),
            32,
        ),
    )
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
            if phase == "initial" and available and not tools:
                raise ValueError(
                    f"initial plan selected no installed tool for {evidence_id}"
                )
            if len(tools) > max_tools:
                raise ValueError(
                    f"artifact plan exceeded the {max_tools}-tool limit"
                )
            required_capabilities = list(dict.fromkeys(
                str(value).strip()
                for value in artifact.get("required_capabilities") or []
                if str(value).strip()
            ))
            unknown_capabilities = set(required_capabilities) - capability_names
            if unknown_capabilities:
                raise ValueError(
                    f"plan invented capabilities: {sorted(unknown_capabilities)}"
                )
            covered_capabilities = {
                str(capability)
                for tool in tools
                for capability in available[tool["tool_id"]].get("capabilities") or []
            }
            uncovered = set(required_capabilities) - covered_capabilities
            if uncovered:
                raise ValueError(
                    f"selected tools do not cover required capabilities: {sorted(uncovered)}"
                )
            deferred = []
            for item in artifact.get("deferred_tools") or []:
                tool_id = str(item.get("tool_id") or "")
                reason = str(item.get("reason") or "").strip()
                if tool_id not in available or tool_id in selected or not reason:
                    raise ValueError("deferred tool entry was invalid")
                deferred.append({"tool_id": tool_id, "reason": reason[:500]})
            normalized.append({
                "evidence_id": evidence_id,
                "reasoning": str(artifact.get("reasoning") or "")[:2000],
                "required_capabilities": required_capabilities[:20],
                "deferred_tools": deferred[:20],
                "tools": tools,
            })
        missing = evidence_ids - seen
        if missing:
            raise ValueError(f"plan omitted evidence: {sorted(missing)}")
        return {
            "case_objective": str(payload.get("case_objective") or "")[:2000],
            "analysis_strategy": str(
                payload.get("analysis_strategy") or "balanced"
            ),
            "phase": phase,
            "artifacts": normalized,
        }

    prompt = (
        "Chain-of-custody artifact facts:\n"
        f"{json.dumps(_profiles(verified), separators=(',', ':'), default=str)}\n\n"
        "Live tool capabilities and availability:\n"
        f"{json.dumps(status, separators=(',', ':'), default=str)}\n\n"
        "Prior tool results, if this is a follow-up planning pass:\n"
        f"{json.dumps(_compact_prior_analysis(prior_analysis), separators=(',', ':'), default=str)}"
    )
    try:
        schema = json.loads(json.dumps(PLAN_SCHEMA))
        schema["properties"]["artifacts"]["items"]["properties"][
            "tools"
        ]["maxItems"] = max_tools
        return await decide_json(
            agent="forensic_followup" if prior_analysis else "forensic_planner",
            system=SYSTEM_PROMPT,
            prompt=prompt,
            schema=schema,
            validator=validate,
            attempts=int(get_value(
                "forensics",
                "followup_attempts" if prior_analysis else "planner_attempts",
                default=1,
            )),
            num_predict=int(get_value(
                "forensics",
                "followup_num_predict" if prior_analysis else "planner_num_predict",
                default=512 if prior_analysis else 768,
            )),
            transport_retries=0,
            timeout_seconds=float(get_value(
                "forensics",
                "followup_timeout_seconds" if prior_analysis else "planner_timeout_seconds",
                default=90 if prior_analysis else 120,
            )),
        )
    except AgentDecisionError as exc:
        return {
            "case_objective": "Planner unavailable; no analytical tool was selected.",
            "analysis_strategy": "rapid",
            "phase": phase,
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
