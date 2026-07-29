"""Evidence-cited forensic interpretation owned by a local agent model."""
from __future__ import annotations

import json
import re
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json


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

    prompt_payload = {
        "inventory": triage.get("inventory") or [],
        "warnings": triage.get("warnings") or [],
        "event_histogram": correlation.get("event_histogram") or {},
        "evidence_facts": correlation.get("evidence_facts") or [],
        "records": [
            {
                key: record.get(key)
                for key in (
                    "_record_ref",
                    "_evidence_id",
                    "timestamp",
                    "host",
                    "user",
                    "event",
                    "src_ip",
                    "dst_ip",
                    "detail",
                    "source_file",
                )
            }
            for record in (triage.get("records") or [])[:500]
        ],
    }
    try:
        result = await decide_json(
            agent="forensic_analysis",
            system=SYSTEM_PROMPT,
            prompt=(
                "Interpret this verified forensic evidence package:\n"
                f"{json.dumps(prompt_payload, indent=2, default=str)[:120000]}"
            ),
            schema=INTERPRETATION_SCHEMA,
            validator=validate,
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
