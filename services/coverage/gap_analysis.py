"""Agent-owned ATT&CK telemetry coverage assessment with cited records."""
from __future__ import annotations

from collections import Counter
import json
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.knowledge import mitre
from services.orchestration.state import HuntState


COVERAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "overall_status": {
            "type": "string",
            "enum": ["covered", "partial", "not_testable", "unknown"],
        },
        "data_sources": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "data_source": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": [
                            "covered",
                            "partial",
                            "not_covered",
                            "unknown",
                        ],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "reason": {"type": "string"},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "missing_requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "data_source",
                    "status",
                    "confidence",
                    "reason",
                    "evidence_refs",
                    "missing_requirements",
                ],
            },
        },
        "gaps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["overall_status", "data_sources", "gaps"],
}


SYSTEM_PROMPT = """You are THOS's telemetry coverage specialist. Decide
whether the actual queried telemetry can test each governed ATT&CK data source
for the current hypothesis.

Rules:
- distinguish connector availability, source capability, current query scope,
  and actual observed records;
- do not infer that a source lacks a data type merely because one query or
  sample did not return it;
- covered requires cited records that materially represent the ATT&CK data
  source; partial means related telemetry exists but a required component,
  field, audit setting, retention interval, or entity context is missing;
- not_covered requires evidence that the selected source cannot provide or did
  not collect the required telemetry; use unknown when the supplied evidence
  cannot establish coverage;
- cite exact record:<index> references for claims based on telemetry;
- identify concrete collection, retention, parsing, schema, or query gaps;
- never use event count alone as the coverage decision.

Return one row for every supplied ATT&CK data source and only schema-valid
JSON."""


async def coverage_gap_node(state: HuntState) -> dict:
    logs = list(state.get("processed_logs") or [])
    technique_id = str(state.get("technique_id") or "")
    technique = mitre.map_technique(technique_id) or {}
    required_sources = [
        str(value) for value in technique.get("data_sources") or []
    ]
    diagnostics = state.get("source_diagnostics") or {}
    selected_sources = list(dict.fromkeys(
        str(source).lower()
        for source in (
            state.get("siem_types")
            or [state.get("siem_type")]
        )
        if source not in (None, "") and str(source).strip()
    ))
    if not required_sources:
        assessment = {
            "technique_id": technique_id,
            "technique_name": (
                technique.get("name") or state.get("technique_name") or ""
            ),
            "status": "unknown",
            "required_source_count": 0,
            "covered_source_count": 0,
            "partial_source_count": 0,
            "unavailable_source_count": 0,
            "data_sources": [],
            "observed_device_types": dict(Counter(
                str(log.get("device_type") or "unknown") for log in logs
            )),
            "observed_event_categories": dict(Counter(
                str(log.get("event_category") or "unknown") for log in logs
            )),
            "decision_owner": "coverage_gap_model",
            "degraded": False,
        }
        return {
            "coverage_assessment": assessment,
            "coverage_gaps": [
                f"ATT&CK {technique_id or 'unmapped'} has no governed "
                "data-source mapping in the local technique catalog."
            ],
        }
    known_refs = {f"record:{index}" for index in range(len(logs))}

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        rows = payload.get("data_sources")
        if not isinstance(rows, list):
            raise ValueError("data_sources was not a list")
        by_name = {}
        for row in rows:
            name = str(row.get("data_source") or "")
            if name not in required_sources or name in by_name:
                raise ValueError(f"invalid or duplicate data source {name}")
            refs = list(dict.fromkeys(
                str(value) for value in row.get("evidence_refs") or []
            ))
            if any(ref not in known_refs for ref in refs):
                raise ValueError(f"{name} cited an unknown record")
            if row.get("status") == "covered" and not refs:
                raise ValueError(f"{name} claimed coverage without a record")
            by_name[name] = {
                "data_source": name,
                "status": row.get("status"),
                "confidence": row.get("confidence"),
                "reason": str(row.get("reason") or "")[:3000],
                "evidence_refs": refs,
                "missing_requirements": [
                    str(value)[:1000]
                    for value in row.get("missing_requirements") or []
                ],
            }
        if set(by_name) != set(required_sources):
            raise ValueError("coverage assessment omitted a required data source")
        return {
            "overall_status": payload.get("overall_status"),
            "data_sources": [by_name[name] for name in required_sources],
            "gaps": [
                str(value)[:3000]
                for value in payload.get("gaps") or []
                if str(value).strip()
            ],
        }

    record_sample = [
        {
            "_coverage_ref": f"record:{index}",
            **{
                key: value
                for key, value in record.items()
                if key not in {"_raw"} and value not in (None, "", [], {})
            },
        }
        for index, record in enumerate(logs[:300])
    ]
    prompt = (
        f"Technique: {technique_id} {technique.get('name') or ''}\n"
        f"Required ATT&CK data sources: {json.dumps(required_sources)}\n"
        f"Selected telemetry sources: {json.dumps(selected_sources)}\n"
        f"Connector/query diagnostics: {json.dumps(diagnostics, default=str)}\n"
        "Observed category histogram: "
        f"{json.dumps(Counter(str(log.get('event_category') or 'unknown') for log in logs))}\n"
        "Observed device histogram: "
        f"{json.dumps(Counter(str(log.get('device_type') or 'unknown') for log in logs))}\n"
        f"Referenced record sample:\n{json.dumps(record_sample, default=str)[:100000]}"
    )
    try:
        decision = await decide_json(
            agent="coverage_gap",
            system=SYSTEM_PROMPT,
            prompt=prompt,
            schema=COVERAGE_SCHEMA,
            validator=validate,
        )
        degraded = False
        error = ""
    except AgentDecisionError as exc:
        decision = {
            "overall_status": "unknown",
            "data_sources": [
                {
                    "data_source": source,
                    "status": "unknown",
                    "confidence": "low",
                    "reason": "Coverage agent did not return a validated assessment.",
                    "evidence_refs": [],
                    "missing_requirements": [],
                }
                for source in required_sources
            ],
            "gaps": [str(exc)],
        }
        degraded = True
        error = str(exc)
    rows = decision["data_sources"]
    factual_gaps = []
    for source in selected_sources:
        diagnostic = diagnostics.get(source) or {}
        if not diagnostic:
            factual_gaps.append(
                f"Selected telemetry source `{source}` has not been queried."
            )
        elif diagnostic.get("status") in {
            "unavailable", "query_generation_failed"
        }:
            factual_gaps.append(
                f"Selected telemetry source `{source}` could not be evaluated: "
                f"{diagnostic.get('error') or diagnostic.get('status')}."
            )
    assessment = {
        "technique_id": technique_id,
        "technique_name": (
            technique.get("name") or state.get("technique_name") or ""
        ),
        "status": decision["overall_status"],
        "required_source_count": len(rows),
        "covered_source_count": sum(
            row["status"] == "covered" for row in rows
        ),
        "partial_source_count": sum(
            row["status"] == "partial" for row in rows
        ),
        "unavailable_source_count": sum(
            row["status"] == "not_covered" for row in rows
        ),
        "data_sources": rows,
        "observed_device_types": dict(Counter(
            str(log.get("device_type") or "unknown") for log in logs
        )),
        "observed_event_categories": dict(Counter(
            str(log.get("event_category") or "unknown") for log in logs
        )),
        "decision_owner": "coverage_gap_model",
        "degraded": degraded,
        "error": error,
    }
    return {
        "coverage_assessment": assessment,
        "coverage_gaps": list(dict.fromkeys([
            *decision.get("gaps", []),
            *factual_gaps,
        ])),
    }
