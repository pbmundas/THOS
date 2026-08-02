"""Evidence-cited forensic interpretation owned by a local agent model."""
from __future__ import annotations

import json
import re
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.runtime_config import get_value


INTERPRETATION_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "overall_disposition": {
            "type": "string",
            "enum": [
                "confirmed_malicious",
                "likely_malicious",
                "suspicious",
                "benign_explained",
                "inconclusive",
            ],
        },
        "proven_facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["claim", "evidence_refs"],
            },
        },
        "activity_assessments": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "classification": {
                        "type": "string",
                        "enum": [
                            "confirmed_malicious",
                            "likely_malicious",
                            "suspicious",
                            "benign_explained",
                            "unresolved",
                        ],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "claim": {"type": "string"},
                    "basis": {"type": "string"},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "classification",
                    "confidence",
                    "claim",
                    "basis",
                    "evidence_refs",
                    "mitre_techniques",
                ],
            },
        },
        "unresolved_anomalies": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "summary",
        "overall_disposition",
        "proven_facts",
        "activity_assessments",
        "unresolved_anomalies",
        "recommendations",
    ],
}


SYSTEM_PROMPT = """You are THOS's senior digital forensic examiner. Interpret
only the supplied verified evidence, parsed records, detection-rule facts,
YARA facts, threat-intelligence facts, and tool results.

Experienced-examiner requirements:
- distinguish tool output, observable fact, inference, and final disposition;
- a rule, signature, reputation, anomaly, packer, string, or capability match
  is evidence to correlate, never an automatic malicious verdict;
- cite every claim with exact supplied evidence, record, or fact references;
- evaluate alternative benign explanations and provenance such as controlled
  testing when the evidence contains it;
- map ATT&CK only when supported by behavior in cited evidence;
- state what missing logs, memory context, encryption, corruption, anti-
  forensics, overwrites, unsupported formats, or unavailable tools prevent
  determination;
- do not invent execution, persistence, identity, intent, network traffic,
  malware family, attribution, or compromise;
- use confirmed_malicious only when cited facts directly establish malicious
  behavior, not merely suspicion or a vendor label.

Return only schema-valid JSON."""


def _known_references(triage: dict, correlation: dict) -> set[str]:
    references = {
        str(item.get("evidence_id"))
        for item in triage.get("inventory") or []
        if item.get("evidence_id")
    }
    references.update(
        str(item.get("_record_ref"))
        for item in triage.get("records") or []
        if item.get("_record_ref")
    )
    references.update(
        str(item.get("fact_id"))
        for item in correlation.get("evidence_facts") or []
        if item.get("fact_id")
    )
    return references


def _bounded_evidence_package(triage: dict, correlation: dict) -> dict:
    inventory_cap = max(
        1, int(get_value("forensics", "interpretation_inventory_cap", default=200))
    )
    plan_artifact_cap = max(
        1,
        int(get_value(
            "forensics", "interpretation_plan_artifact_cap", default=200
        )),
    )
    record_cap = max(
        1, int(get_value("forensics", "interpretation_record_cap", default=80))
    )
    record_char_cap = max(
        200,
        int(get_value(
            "forensics", "interpretation_record_char_cap", default=900
        )),
    )
    fact_cap = max(
        1, int(get_value("forensics", "interpretation_fact_cap", default=120))
    )
    fact_char_cap = max(
        200,
        int(get_value(
            "forensics", "interpretation_fact_char_cap", default=1600
        )),
    )
    all_facts = [
        item for item in correlation.get("evidence_facts") or []
        if isinstance(item, dict)
    ]

    def fact_priority(item: dict) -> tuple[int, str]:
        fact_type = str(item.get("fact_type") or "")
        status = str(item.get("status") or "")
        material = fact_type in {
            "yara_rule_match", "threat_intelligence_match"
        }
        limitation = status in {"failed", "timed_out", "invalid_plan"}
        return (0 if material else 1 if limitation else 2, str(item.get("fact_id")))

    facts = sorted(all_facts, key=fact_priority)[:fact_cap]
    compact_facts = []
    referenced_records: list[str] = []
    referenced_record_set: set[str] = set()

    def bounded_value(value: Any, limit: int) -> Any:
        if isinstance(value, str):
            return value[:limit]
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, separators=(",", ":"), default=str)[:limit]
        return value

    all_inventory = [
        item for item in triage.get("inventory") or [] if isinstance(item, dict)
    ]
    inventory = [
        {
            key: bounded_value(value, 500)
            for key, value in item.items()
            if key in {
                "evidence_id", "original_name", "stored_name", "size_bytes",
                "sha256", "extension", "magic_hex",
            }
        }
        for item in all_inventory[:inventory_cap]
    ]

    def bounded_plan(value: Any) -> dict:
        if not isinstance(value, dict):
            return {}
        return {
            "case_objective": str(value.get("case_objective") or "")[:2000],
            "analysis_strategy": value.get("analysis_strategy"),
            "phase": value.get("phase"),
            "artifacts": [
                {
                    "evidence_id": item.get("evidence_id"),
                    "reasoning": str(item.get("reasoning") or "")[:1000],
                    "required_capabilities": list(
                        item.get("required_capabilities") or []
                    )[:20],
                    "tools": [
                        {
                            "tool_id": tool.get("tool_id"),
                            "objective": str(tool.get("objective") or "")[:500],
                        }
                        for tool in item.get("tools") or []
                        if isinstance(tool, dict)
                    ][:32],
                }
                for item in value.get("artifacts") or []
                if isinstance(item, dict)
            ][:plan_artifact_cap],
        }

    for item in facts:
        refs = [str(value) for value in item.get("evidence_refs") or []]
        for ref in refs:
            if ":" in ref and ref not in referenced_record_set:
                referenced_record_set.add(ref)
                referenced_records.append(ref)
        compact_facts.append({
            key: (
                bounded_value(value, fact_char_cap)
            )
            for key, value in item.items()
            if key in {
                "fact_id", "fact_type", "evidence_refs", "tool_id",
                "status", "exit_code", "output", "data", "error", "note",
                "rule_id", "namespace", "metadata", "strings", "indicator",
                "matched_indicator", "category", "severity", "confidence",
                "sources", "last_seen",
            }
        })
    all_records = list(triage.get("records") or [])
    record_indices = {
        str(record.get("_record_ref") or ""): index
        for index, record in enumerate(all_records)
        if record.get("_record_ref")
    }
    priority_indices = [
        record_indices[ref] for ref in referenced_records if ref in record_indices
    ]
    if len(all_records) <= record_cap:
        sample_indices = list(range(len(all_records)))
    else:
        stride_indices = [
            min(len(all_records) - 1, int(index * len(all_records) / record_cap))
            for index in range(record_cap)
        ]
        sample_indices = []
        for index in [*priority_indices, *stride_indices]:
            if index not in sample_indices:
                sample_indices.append(index)
            if len(sample_indices) >= record_cap:
                break
    records = []
    for index in sample_indices:
        record = all_records[index]
        records.append({
            key: (
                bounded_value(record.get(key), record_char_cap)
            )
            for key in (
                "_record_ref", "_evidence_id", "timestamp", "host", "user",
                "event", "src_ip", "dst_ip", "detail", "source_file",
            )
        })
    return {
        "inventory": inventory,
        "warnings": [
            str(value)[:1000] for value in triage.get("warnings") or []
        ][:40],
        "event_histogram": correlation.get("event_histogram") or {},
        "tool_plan": bounded_plan(triage.get("tool_plan")),
        "followup_tool_plan": bounded_plan(triage.get("followup_tool_plan")),
        "evidence_facts": compact_facts,
        "records": records,
        "resource_bounds": {
            "total_records": len(all_records),
            "records_supplied": len(records),
            "records_omitted": max(0, len(all_records) - len(records)),
            "total_facts": len(all_facts),
            "facts_supplied": len(compact_facts),
            "facts_omitted": max(0, len(all_facts) - len(compact_facts)),
            "total_inventory_items": len(all_inventory),
            "inventory_items_supplied": len(inventory),
            "inventory_items_omitted": max(
                0, len(all_inventory) - len(inventory)
            ),
        },
    }


async def interpret_forensic_evidence(
    triage: dict,
    correlation: dict,
) -> dict:
    known_refs = _known_references(triage, correlation)

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        summary = str(payload.get("summary") or "").strip()
        if not summary:
            raise ValueError("summary was empty")
        disposition = str(payload.get("overall_disposition") or "")
        allowed_dispositions = {
            "confirmed_malicious",
            "likely_malicious",
            "suspicious",
            "benign_explained",
            "inconclusive",
        }
        if disposition not in allowed_dispositions:
            raise ValueError("overall disposition was invalid")

        def checked_refs(values: Any, label: str) -> list[str]:
            refs = list(dict.fromkeys(
                str(value) for value in (values or []) if str(value).strip()
            ))
            if not refs:
                raise ValueError(f"{label} omitted evidence references")
            malformed = [ref for ref in refs if ref not in known_refs]
            if malformed:
                raise ValueError(
                    f"{label} cited unknown references: {malformed[:5]}"
                )
            return refs

        facts = []
        for index, item in enumerate(payload.get("proven_facts") or []):
            claim = str(item.get("claim") or "").strip()
            if not claim:
                raise ValueError(f"proven fact {index} had no claim")
            facts.append({
                "claim": claim[:3000],
                "evidence_refs": checked_refs(
                    item.get("evidence_refs"), f"proven fact {index}"
                ),
            })
        assessments = []
        for index, item in enumerate(
            payload.get("activity_assessments") or []
        ):
            refs = checked_refs(
                item.get("evidence_refs"), f"assessment {index}"
            )
            techniques = list(dict.fromkeys(
                str(value).upper()
                for value in item.get("mitre_techniques") or []
                if re.fullmatch(
                    r"T\d{4}(?:\.\d{3})?",
                    str(value),
                    re.IGNORECASE,
                )
            ))
            assessments.append({
                "ref": refs[0],
                "evidence_refs": refs,
                "classification": str(item.get("classification") or ""),
                "confidence": str(item.get("confidence") or ""),
                "claim": str(item.get("claim") or "")[:3000],
                "basis": str(item.get("basis") or "")[:4000],
                "mitre_techniques": techniques,
            })
        return {
            "summary": summary[:6000],
            "overall_disposition": disposition,
            "proven_facts": facts,
            "activity_assessments": assessments,
            "unresolved_anomalies": [
                str(value)[:3000]
                for value in payload.get("unresolved_anomalies") or []
                if str(value).strip()
            ],
            "recommendations": [
                str(value)[:3000]
                for value in payload.get("recommendations") or []
                if str(value).strip()
            ],
        }

    prompt_payload = _bounded_evidence_package(triage, correlation)
    try:
        result = await decide_json(
            agent="forensic_analysis",
            system=SYSTEM_PROMPT,
            prompt=(
                "Interpret this verified forensic evidence package:\n"
                f"{json.dumps(prompt_payload, separators=(',', ':'), default=str)}"
            ),
            schema=INTERPRETATION_SCHEMA,
            validator=validate,
            attempts=int(get_value(
                "forensics", "interpretation_attempts", default=2
            )),
            num_predict=int(get_value(
                "forensics", "interpretation_num_predict", default=1400
            )),
            transport_retries=0,
            timeout_seconds=float(get_value(
                "forensics", "interpretation_timeout_seconds", default=240
            )),
        )
        return {**correlation, **result, "interpretation_status": "completed"}
    except AgentDecisionError as exc:
        return {
            **correlation,
            "summary": (
                "The forensic interpretation model did not return a validated "
                "evidence-cited assessment."
            ),
            "overall_disposition": "inconclusive",
            "proven_facts": [],
            "activity_assessments": [],
            "unresolved_anomalies": [str(exc)],
            "recommendations": [
                "Retry interpretation with a healthy configured local reasoning model."
            ],
            "interpretation_status": "model_unavailable",
            "interpretation_error": str(exc),
        }
