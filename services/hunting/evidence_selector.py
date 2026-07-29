"""Model-owned selection of hypothesis-relevant telemetry evidence."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.runtime_config import get_value


EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "assessment": {"type": "string"},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "record_index": {"type": "integer"},
                    "kind": {
                        "type": "string",
                        "enum": ["behavioral", "artifact"],
                    },
                    "claim": {"type": "string"},
                    "matched_literals": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "record_index",
                    "kind",
                    "claim",
                    "matched_literals",
                ],
            },
        },
    },
    "required": ["assessment", "evidence"],
}


SYSTEM_PROMPT = """You are THOS's threat-hunt evidence selection agent.
Review the supplied normalized records against the exact hypothesis,
investigation objective, ATT&CK context, governed indicator references, and
deterministic detection-rule match references.

Experienced-hunter requirements:
- select only records that contain literal, hypothesis-relevant behavior or
  artifacts; a record merely returned by a broad search is not evidence;
- preserve controlled-test, rehearsal, simulation, or compliance records when
  they really contain the investigated behavior; their context affects intent,
  not whether the behavior was observed;
- distinguish behavioral evidence from literal artifacts such as a command,
  process, file, protocol action, address, account, or governed identifier;
- every matched literal must occur verbatim in the cited record;
- do not infer a tool, behavior, intent, compromise, or ATT&CK technique from
  an unrelated event;
- an empty evidence array is correct when the retrieved records do not match.

Return only schema-valid JSON with exact supplied record_index values."""


def _record_text(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)


async def select_hunt_evidence(
    *,
    logs: list[dict],
    hypothesis_text: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    objective: str,
    indicators: dict,
    detection_rule_refs: list[int],
) -> dict:
    cap = max(
        1,
        int(
            get_value(
                "autonomy",
                "evidence_selection_record_cap",
                default=500,
            )
        ),
    )
    prioritized = []
    seen = set()
    for index in [*detection_rule_refs, *range(len(logs))]:
        if index in seen or not 0 <= index < len(logs):
            continue
        seen.add(index)
        prioritized.append(index)
        if len(prioritized) >= cap:
            break
    supplied = [
        {
            "record_index": index,
            "record": logs[index],
            "detection_rule_match": index in set(detection_rule_refs),
        }
        for index in prioritized
    ]
    supplied_indices = set(prioritized)

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        selected = []
        seen_pairs = set()
        for item in payload.get("evidence") or []:
            index = int(item.get("record_index"))
            kind = str(item.get("kind") or "")
            if index not in supplied_indices:
                raise ValueError(
                    f"evidence cited unsupplied record index {index}"
                )
            pair = (index, kind)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            claim = str(item.get("claim") or "").strip()
            if not claim:
                raise ValueError("evidence claim was empty")
            record_text = _record_text(logs[index]).lower()
            literals = list(dict.fromkeys(
                str(value).strip()
                for value in item.get("matched_literals") or []
                if str(value).strip()
            ))
            if not literals:
                raise ValueError("evidence omitted matched literals")
            if any(literal.lower() not in record_text for literal in literals):
                raise ValueError(
                    f"evidence for record {index} cited a non-literal value"
                )
            selected.append({
                "record_index": index,
                "event": str(logs[index].get("event") or "unknown"),
                "kind": kind,
                "claim": claim[:2000],
                "matched_literals": literals[:20],
                "evidence": str(
                    logs[index].get("evidence_summary")
                    or logs[index].get("detail")
                    or logs[index].get("event")
                    or ""
                )[:2000],
            })
        return {
            "assessment": str(payload.get("assessment") or "")[:3000],
            "evidence": selected,
            "records_supplied": len(supplied),
            "records_omitted_by_resource_bound": max(
                0, len(logs) - len(supplied)
            ),
        }

    try:
        return await decide_json(
            agent="evidence_selector",
            system=SYSTEM_PROMPT,
            prompt=json.dumps({
                "hypothesis": hypothesis_text,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
                "current_objective": objective,
                "governed_indicators": indicators,
                "records": supplied,
            }, indent=2, default=str)[:120000],
            schema=EVIDENCE_SCHEMA,
            validator=validate,
        )
    except AgentDecisionError as exc:
        return {
            "assessment": "",
            "evidence": [],
            "records_supplied": len(supplied),
            "records_omitted_by_resource_bound": max(
                0, len(logs) - len(supplied)
            ),
            "_decision_metadata": {
                "owner": "evidence_selector_model",
                "degraded": True,
                "error": str(exc),
            },
        }
