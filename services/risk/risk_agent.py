"""Evidence-grounded Risk Analysis Agent.

Deterministic code extracts and validates source facts. The local model decides
whether those facts describe an actionable risk and assigns the explanation,
entity, score, severity, and rationale.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.runtime_config import get_value


RISK_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "what": {"type": "string"},
                    "why": {"type": "string"},
                    "discovery": {"type": "string"},
                    "entity_type": {"type": "string"},
                    "entity_name": {"type": "string"},
                    "score": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "candidate_id",
                    "name",
                    "description",
                    "what",
                    "why",
                    "discovery",
                    "entity_type",
                    "entity_name",
                    "score",
                    "severity",
                    "evidence_refs",
                ],
            },
        },
        "excluded_candidates": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["items", "excluded_candidates"],
}


SYSTEM_PROMPT = """You are THOS's senior cyber-risk analysis agent. Review
validated hunt findings and persisted detection evidence and decide which
entries represent actionable risks.

Requirements:
- use only supplied evidence and exact candidate identifiers;
- exclude negative findings, unsupported claims, routine expected behavior,
  controlled testing that creates no residual exposure, and detections that do
  not establish a plausible security risk;
- controlled-test evidence can still reveal a risk when it proves an exposed
  control, vulnerable asset, missing containment, or operational gap;
- explain what the risk is, why it matters, how it was discovered, and which
  entity is affected;
- score 1-100 by evidence-supported likelihood, impact, exposure, asset
  relevance, control effectiveness, and uncertainty; do not score from tool
  names, ATT&CK tactics, keywords, event counts, or rule severity alone;
- select an entity only when its literal value appears in the candidate;
- never convert a rule, reputation, IOC, anomaly, or model label directly into
  a verdict;
- cite every risk with one or more exact candidate identifiers.

Return only schema-valid JSON. It is valid to return no risks."""


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _title(markdown: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", markdown, flags=re.MULTILINE)
    return re.sub(r"[*_`]", "", match.group(1)).strip() if match else fallback


def _section_bullets(markdown: str, heading: str) -> list[str]:
    match = re.search(
        rf"^###?\s+.*{re.escape(heading)}.*$([\s\S]*?)(?=^###?\s+|\Z)",
        markdown,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return []
    return [
        re.sub(r"^\s*[-*]\s+", "", line).strip()[:3000]
        for line in match.group(1).splitlines()
        if re.match(r"^\s*[-*]\s+\S", line)
    ]


def _verified_report(markdown: str) -> bool:
    return bool(re.search(
        r"Verifier[\s\S]{0,800}?(?:`passed`|Passed:|status.{0,20}passed)",
        markdown,
        flags=re.IGNORECASE,
    ))


def _report_candidates(hunts: list[dict], reports_root: Path) -> list[dict]:
    candidates = []
    for hunt in hunts:
        if hunt.get("status") != "completed" or not hunt.get("report_path"):
            continue
        path = reports_root / Path(str(hunt["report_path"])).name
        if not path.is_file():
            continue
        markdown = path.read_text(encoding="utf-8", errors="replace")
        if not _verified_report(markdown):
            continue
        findings = _section_bullets(markdown, "Security Findings")
        for index, finding in enumerate(findings):
            candidate_id = f"report:{hunt.get('hunt_id')}:{index}"
            candidates.append({
                "candidate_id": candidate_id,
                "source_type": "hunt_report",
                "source_id": str(hunt.get("hunt_id") or ""),
                "source_label": _title(markdown, path.stem),
                "report_filename": path.name,
                "hypothesis_id": str(hunt.get("hypothesis_id") or ""),
                "finding": finding,
                "context_excerpt": markdown[:16000],
                "identified_at": _timestamp(hunt.get("created_at")),
                "last_seen_at": _timestamp(
                    hunt.get("updated_at") or hunt.get("created_at")
                ),
            })
    return candidates


def _detection_candidates(detections: list[dict]) -> list[dict]:
    candidates = []
    for detection in detections:
        matched = int(detection.get("events_matched") or 0)
        if matched <= 0:
            continue
        run_id = str(detection.get("run_id") or "")
        candidates.append({
            "candidate_id": f"detection:{run_id}",
            "source_type": "detection",
            "source_id": str(detection.get("rule_id") or ""),
            "source_label": str(
                detection.get("rule_title")
                or detection.get("rule_id")
                or "Detection"
            ),
            "detection_run_id": run_id,
            "events_matched": matched,
            "rule_metadata": {
                key: detection.get(key)
                for key in ("rule_id", "rule_title", "level", "siem_type")
            },
            "analysis": detection.get("analysis") or {},
            "matched_events": (detection.get("matched_events") or [])[:50],
            "identified_at": _timestamp(detection.get("created_at")),
            "last_seen_at": _timestamp(
                (detection.get("analysis") or {}).get("last_event_at")
                or detection.get("created_at")
            ),
        })
    return candidates


def _risk_id(item: dict, candidate: dict) -> str:
    material = "|".join((
        str(candidate.get("source_type") or ""),
        str(candidate.get("source_id") or ""),
        str(item.get("name") or "").casefold(),
        str(item.get("entity_name") or "").casefold(),
    ))
    return "risk-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


async def _analyze_batch(candidates: list[dict]) -> dict:
    by_id = {str(item["candidate_id"]): item for item in candidates}
    rendered = {
        candidate_id: json.dumps(candidate, ensure_ascii=False, default=str)
        for candidate_id, candidate in by_id.items()
    }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        normalized = []
        seen = set()
        for item in payload.get("items") or []:
            candidate_id = str(item.get("candidate_id") or "")
            candidate = by_id.get(candidate_id)
            if not candidate or candidate_id in seen:
                raise ValueError(
                    f"risk referenced invalid/duplicate candidate {candidate_id}"
                )
            seen.add(candidate_id)
            evidence_refs = list(dict.fromkeys(
                str(value) for value in item.get("evidence_refs") or []
            ))
            if not evidence_refs or any(ref not in by_id for ref in evidence_refs):
                raise ValueError("risk evidence references were invalid")
            entity_name = str(item.get("entity_name") or "").strip()
            if not entity_name or entity_name.casefold() not in rendered[
                candidate_id
            ].casefold():
                raise ValueError(
                    f"entity {entity_name!r} was not grounded in {candidate_id}"
                )
            score = int(item.get("score"))
            if not 1 <= score <= 100:
                raise ValueError("risk score was outside 1-100")
            normalized.append({
                **item,
                "candidate_id": candidate_id,
                "name": str(item.get("name") or "")[:180],
                "description": str(item.get("description") or "")[:5000],
                "what": str(item.get("what") or "")[:3000],
                "why": str(item.get("why") or "")[:3000],
                "discovery": str(item.get("discovery") or "")[:3000],
                "entity_type": str(item.get("entity_type") or "")[:120],
                "entity_name": entity_name[:500],
                "score": score,
                "evidence_refs": evidence_refs,
            })
        return {
            "items": normalized,
            "excluded_candidates": [
                str(value)
                for value in payload.get("excluded_candidates") or []
                if str(value) in by_id
            ],
        }

    return await decide_json(
        agent="risk_analysis",
        system=SYSTEM_PROMPT,
        prompt=(
            "Validated risk candidates:\n"
            f"{json.dumps(candidates, indent=2, default=str)[:120000]}"
        ),
        schema=RISK_SCHEMA,
        validator=validate,
    )


async def analyze_actionable_risks(
    hunts: list[dict],
    detections: list[dict],
    reports_dir: str | Path,
    limit: int = 500,
    hours: int | None = None,
) -> dict:
    """Return risks selected and explained by the Risk Analysis Agent."""
    candidates = [
        *_report_candidates(hunts, Path(reports_dir)),
        *_detection_candidates(detections),
    ]
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=max(1, min(int(hours), 24 * 365 * 10))
        )
        candidates = [
            item
            for item in candidates
            if datetime.fromisoformat(item["identified_at"]) >= cutoff
        ]
    candidate_by_id = {
        str(item["candidate_id"]): item for item in candidates
    }
    batch_size = max(
        1,
        min(
            int(get_value("autonomy", "risk_batch_size", default=40)),
            100,
        ),
    )
    model_items = []
    failures = []
    for start in range(0, len(candidates), batch_size):
        batch = candidates[start:start + batch_size]
        try:
            result = await _analyze_batch(batch)
            model_items.extend(result.get("items") or [])
        except AgentDecisionError as exc:
            failures.append(str(exc))
    risks = []
    for item in model_items:
        candidate = candidate_by_id[item["candidate_id"]]
        risks.append({
            "id": _risk_id(item, candidate),
            "name": item["name"],
            "description": item["description"],
            "what": item["what"],
            "why": item["why"],
            "discovery": item["discovery"],
            "entity": {
                "type": item["entity_type"],
                "name": item["entity_name"],
            },
            "score": item["score"],
            "severity": item["severity"],
            "identified_at": candidate["identified_at"],
            "last_seen_at": candidate["last_seen_at"],
            "source_type": candidate["source_type"],
            "source_label": candidate["source_label"],
            "source_id": candidate["source_id"],
            "report_filename": candidate.get("report_filename", ""),
            "detection_run_id": candidate.get("detection_run_id", ""),
            "evidence_count": len(item["evidence_refs"]),
            "evidence_refs": item["evidence_refs"],
            "status": "open",
        })
    risks.sort(
        key=lambda item: (item["score"], item["last_seen_at"]),
        reverse=True,
    )
    risks = risks[:max(1, min(int(limit), 2000))]
    entities = {
        f"{item['entity']['type']}:{item['entity']['name']}" for item in risks
    }
    summary = {
        "total": len(risks),
        "critical": sum(item["severity"] == "critical" for item in risks),
        "high": sum(item["severity"] == "high" for item in risks),
        "medium": sum(item["severity"] == "medium" for item in risks),
        "low": sum(item["severity"] == "low" for item in risks),
        "affected_entities": len(entities),
        "average_score": round(
            sum(item["score"] for item in risks) / len(risks), 1
        ) if risks else 0,
        "report_findings": sum(
            item["source_type"] == "hunt_report" for item in risks
        ),
        "detection_findings": sum(
            item["source_type"] == "detection" for item in risks
        ),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent": {
            "id": "risk_analysis",
            "name": "Risk Analysis Agent",
            "mode": "local model with deterministic evidence validation",
            "degraded": bool(failures),
            "errors": failures,
        },
        "summary": summary,
        "items": risks,
    }
