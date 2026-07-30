"""Model-owned selection of hypothesis-relevant telemetry evidence."""
from __future__ import annotations

import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.hunting.query_generator import _grounded_query_literals
from services.runtime_config import get_value


EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "assessment": {"type": "string", "maxLength": 300},
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
                    "claim": {"type": "string", "maxLength": 180},
                    "matched_literals": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "maxLength": 120,
                        },
                        "maxItems": 4,
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
- make each evidence claim describe only its cited record; reserve multi-host,
  multi-event, sequence, frequency, and intent conclusions for the assessment
  and only when the supplied records collectively establish them;
- every matched literal must occur verbatim in the cited record;
- do not infer a tool, behavior, intent, compromise, or ATT&CK technique from
  an unrelated event;
- an empty evidence array is correct when the retrieved records do not match.
- when grounded_candidate_refs is non-empty, cite at least one of those records;
  deterministic matching has confirmed that each contains multiple supplied
  hypothesis or governed-indicator literals.

Return only schema-valid JSON with exact supplied record_index values."""


def _record_text(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)


def _model_record(record: dict, char_cap: int) -> dict:
    """Remove duplicated raw payloads while retaining normalized evidence."""
    compact: dict[str, Any] = {}
    has_summary = bool(str(record.get("evidence_summary") or "").strip())
    ordered_keys = [
        *(["evidence_summary"] if has_summary else []),
        *[key for key in record if key != "evidence_summary"],
    ]
    for key in ordered_keys:
        if key == "_raw":
            continue
        if has_summary and key in {"detail", "full_log"}:
            continue
        value = record.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            bounded_value: Any = value[:1200]
        elif isinstance(value, (bool, int, float)):
            bounded_value = value
        else:
            serialized = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
            bounded_value = value if len(serialized) <= 1200 else serialized[:1200]
        candidate = {**compact, str(key): bounded_value}
        if len(_record_text(candidate)) > char_cap:
            continue
        compact[str(key)] = bounded_value
    return compact


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
    configured_cap = max(
        1,
        int(
            get_value(
                "autonomy",
                "evidence_selection_record_cap",
                default=500,
            )
        ),
    )
    model_cap = max(
        1,
        int(
            get_value(
                "autonomy",
                "evidence_selection_model_record_cap",
                default=4,
            )
        ),
    )
    cap = min(configured_cap, model_cap)
    record_char_cap = max(
        500,
        int(
            get_value(
                "autonomy",
                "evidence_selection_record_char_cap",
                default=1200,
            )
        ),
    )
    evidence_cap = max(
        1,
        int(
            get_value(
                "autonomy",
                "evidence_selection_evidence_cap",
                default=3,
            )
        ),
    )
    grounded_literals = _grounded_query_literals(
        hypothesis_text,
        "",
        {"governed_indicators": indicators},
    )
    searchable_literals = [
        literal.casefold()
        for literal in grounded_literals
        if len(literal.strip()) >= 3
    ]
    grounded_candidate_refs = []
    grounded_candidate_literals: dict[int, list[str]] = {}
    for index, record in enumerate(logs):
        record_text = _record_text(record).casefold()
        matched = {
            literal
            for literal in searchable_literals
            if literal in record_text
        }
        if len(matched) >= 2:
            grounded_candidate_refs.append(index)
            grounded_candidate_literals[index] = sorted(
                matched,
                key=lambda value: (-len(value), value),
            )
    prioritized = []
    seen = set()
    for index in [
        *detection_rule_refs,
        *grounded_candidate_refs,
        *range(len(logs)),
    ]:
        if index in seen or not 0 <= index < len(logs):
            continue
        seen.add(index)
        prioritized.append(index)
        if len(prioritized) >= cap:
            break
    supplied = [
        {
            "record_index": index,
            "record": _model_record(logs[index], record_char_cap),
            "detection_rule_match": index in set(detection_rule_refs),
        }
        for index in prioritized
    ]
    supplied_indices = set(prioritized)
    if not supplied:
        return {
            "assessment": (
                "No normalized telemetry records were supplied, so no "
                "hypothesis-relevant evidence could be selected."
            ),
            "evidence": [],
            "records_supplied": 0,
            "records_omitted_by_resource_bound": 0,
            "_decision_metadata": {
                "owner": "deterministic_empty_input",
                "degraded": False,
            },
        }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        selected = []
        seen_pairs = set()
        evidence_items = payload.get("evidence") or []
        if grounded_candidate_refs and not evidence_items:
            raise ValueError(
                "evidence selection was empty despite grounded candidate records"
            )
        if len(evidence_items) > evidence_cap:
            raise ValueError(
                f"evidence selection exceeded the configured {evidence_cap}-item cap"
            )
        for item in evidence_items:
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
        schema = json.loads(json.dumps(EVIDENCE_SCHEMA))
        schema["properties"]["evidence"]["maxItems"] = evidence_cap
        if grounded_candidate_refs:
            schema["properties"]["evidence"]["minItems"] = 1
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
                "grounded_candidate_refs": [
                    index
                    for index in grounded_candidate_refs
                    if index in supplied_indices
                ],
                "maximum_evidence_items": evidence_cap,
                "records": supplied,
            }, separators=(",", ":"), default=str),
            schema=schema,
            validator=validate,
            attempts=int(
                get_value(
                    "autonomy",
                    "evidence_selection_attempts",
                    default=1,
                )
            ),
            num_predict=int(
                get_value(
                    "autonomy",
                    "evidence_selection_num_predict",
                    default=384,
                )
            ),
            transport_retries=int(
                get_value(
                    "autonomy",
                    "evidence_selection_transport_retries",
                    default=0,
                )
            ),
            timeout_seconds=float(
                get_value(
                    "autonomy",
                    "evidence_selection_timeout_seconds",
                    default=120,
                )
            ),
        )
    except AgentDecisionError as exc:
        grounded_fallback = []
        for index in prioritized:
            literals = grounded_candidate_literals.get(index, [])[:4]
            if len(literals) < 2:
                continue
            grounded_fallback.append({
                "record_index": index,
                "event": str(logs[index].get("event") or "unknown"),
                "kind": "behavioral",
                "claim": (
                    "Record contains multiple governed hypothesis or "
                    f"indicator literals: {', '.join(literals)}."
                )[:2000],
                "matched_literals": literals,
                "evidence": str(
                    logs[index].get("evidence_summary")
                    or logs[index].get("detail")
                    or logs[index].get("event")
                    or ""
                )[:2000],
            })
            if len(grounded_fallback) >= evidence_cap:
                break
        if grounded_fallback:
            return {
                "assessment": (
                    "The bounded model decision was unavailable; exact "
                    "literal validation retained only records containing "
                    "multiple governed hypothesis or indicator values."
                ),
                "evidence": grounded_fallback,
                "records_supplied": len(supplied),
                "records_omitted_by_resource_bound": max(
                    0, len(logs) - len(supplied)
                ),
                "_decision_metadata": {
                    "owner": "deterministic_grounded_fallback",
                    "degraded": True,
                    "error": str(exc),
                },
            }
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
