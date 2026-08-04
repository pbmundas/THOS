"""Evidence-grounded Risk Analysis Agent.

Deterministic code extracts and validates source facts. The local model decides
whether those facts describe an actionable risk and assigns the explanation,
entity, score, severity, and rationale.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from services.agents.decision import AgentDecisionError, decide_json
from services.runtime_config import get_value
from services.capacity import internal_worker_limit


RISK_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string", "maxLength": 160},
                    "name": {"type": "string", "maxLength": 180},
                    "description": {"type": "string", "maxLength": 600},
                    "what": {"type": "string", "maxLength": 400},
                    "why": {"type": "string", "maxLength": 400},
                    "discovery": {"type": "string", "maxLength": 400},
                    "entity_type": {"type": "string", "maxLength": 120},
                    "entity_name": {"type": "string", "maxLength": 500},
                    "score": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 8,
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

RISK_ELIGIBILITY_SCHEMA = {
    "type": "object",
    "properties": {
        "actionable": {"type": "boolean"},
        "rationale": {"type": "string", "maxLength": 300},
    },
    "required": ["actionable", "rationale"],
}

RISK_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "approved": {"type": "boolean"},
        "rationale": {"type": "string", "maxLength": 300},
    },
    "required": ["approved", "rationale"],
}

RISK_DECISION_POLICY_VERSION = "eligibility-and-review-v6"


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
- treat verified suspicious or malicious activity and confirmed attack
  attempts as actionable when they identify an affected entity and warrant
  investigation or mitigation; proven compromise is not required;
- an affected entity may be the evidence-grounded source or initiating actor,
  target or victim, account, process, or asset whose behavior or exposure
  requires investigation; it is not limited to the attack target;
- explain what the risk is, why it matters, how it was discovered, and which
  entity is affected;
- score 1-100 by evidence-supported likelihood, impact, exposure, asset
  relevance, control effectiveness, and uncertainty; do not score from tool
  names, ATT&CK tactics, keywords, event counts, or rule severity alone;
- select an entity only when its literal value appears in the candidate;
- never convert a rule, reputation, IOC, anomaly, or model label directly into
  a verdict;
- for detection candidates, raw matched_events take precedence over the rule
  title and any execution metadata; exclude unrelated raw matches;
- cite every risk with one or more exact candidate identifiers.

Keep each explanation concise and within the response schema's field limits.
Every text field must be one short sentence of at most 25 words. Score and
severity must agree: critical=90-100, high=70-89, medium=40-69, low=1-39.
Return only schema-valid JSON. It is valid to return no risks."""


ELIGIBILITY_SYSTEM_PROMPT = """You are THOS's cyber-risk eligibility agent.
Decide only whether one supplied, verifier-supported evidence candidate proves
an actionable security exposure that warrants a risk-register entry.

Exclude negative or unsupported findings, absence of activity, routine expected
behavior, and detections whose matched records are unrelated to the rule.
For detection candidates, treat raw matched_events as authoritative over rule
titles and execution metadata; a rule title alone never proves its behavior.
Verified suspicious or malicious activity and confirmed attack attempts are
actionable when they identify an affected entity and warrant investigation or
mitigation; do not require proof of compromise. Controlled testing is actionable
only when it proves a residual vulnerable asset, exposed control, missing
containment, or operational gap. Use only supplied evidence. Return the
exact candidate ID, one boolean decision, and one short evidence-grounded
rationale. Candidate association is handled by the caller because exactly one
candidate is supplied. Do not perform the detailed risk write-up in this step."""


RISK_REVIEW_SYSTEM_PROMPT = """You are THOS's independent cyber-risk review
agent. Review one proposed risk against its supplied evidence candidate.
Eligibility has already decided that the candidate warrants a risk-register
entry. Review factual grounding and internal consistency only; do not re-decide
eligibility, demand malicious intent, a named attack tool, attribution, or
proven compromise. The affected entity may be the source or initiating actor,
target or victim, account, process, or asset named in the evidence. Approve
when the proposal stays within the raw evidence. Reject when raw matched events
are unrelated to the rule or proposal, when derived summaries conflict with
raw records, or when the proposal adds unsupported facts or describes benign
behavior as malicious. Raw records take precedence over rule titles, triage
text, and prior model output. Do not add facts or rewrite the proposal. Return
one boolean decision and a short evidence-grounded rationale."""


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


def _explicitly_negative_finding(finding: str) -> bool:
    text = re.sub(r"^\s*\[[^\]]+\]\s*", "", str(finding)).strip()
    return bool(re.match(
        r"^(?:no\s+(?:evidence|indication|signs?|matching|observed)|"
        r"nothing\s+(?:indicates|suggests)|"
        r"(?:the\s+)?activity\s+was\s+not\s+observed)\b",
        text,
        flags=re.IGNORECASE,
    ))


def _verified_report(hunt: dict, markdown: str) -> bool:
    outcome = (
        hunt.get("outcome")
        if isinstance(hunt.get("outcome"), dict)
        else {}
    )
    # Risk promotion requires machine-verifiable provenance. Legacy reports
    # may contain a textual "passed" marker that only checked citation index
    # syntax, and some predate semantic verification metadata entirely. They
    # remain available in report history, but cannot seed the live risk
    # register until they are rerun through the current verifier pipeline.
    return (
        str(outcome.get("verification_status") or "").lower() == "passed"
        and str(outcome.get("report_status") or "").lower() == "generated"
        and not bool(outcome.get("reasoning_degraded"))
        and str(outcome.get("reasoning_mode") or "").lower() == "model"
    )


def _report_candidates(hunts: list[dict], reports_root: Path) -> list[dict]:
    candidates = []
    for hunt in hunts:
        if hunt.get("status") != "completed" or not hunt.get("report_path"):
            continue
        path = reports_root / Path(str(hunt["report_path"])).name
        if not path.is_file():
            continue
        markdown = path.read_text(encoding="utf-8", errors="replace")
        if not _verified_report(hunt, markdown):
            continue
        findings = _section_bullets(markdown, "Findings")
        for index, finding in enumerate(findings):
            if _explicitly_negative_finding(finding):
                continue
            candidate_id = f"report:{hunt.get('hunt_id')}:{index}"
            candidates.append({
                "candidate_id": candidate_id,
                "source_type": "hunt_report",
                "source_id": str(hunt.get("hunt_id") or ""),
                "source_label": _title(markdown, path.stem),
                "report_filename": path.name,
                "hypothesis_id": str(hunt.get("hypothesis_id") or ""),
                "finding": finding,
                "context_excerpt": markdown[:max(
                    1000,
                    min(
                        int(get_value(
                            "autonomy", "risk_report_context_char_cap", default=6000
                        )),
                        20_000,
                    ),
                )],
                "identified_at": _timestamp(hunt.get("created_at")),
                "last_seen_at": _timestamp(
                    hunt.get("updated_at") or hunt.get("created_at")
                ),
            })
    return candidates


_RULE_RELEVANCE_STOPWORDS = {
    "activity", "attempt", "attempted", "detected", "detection", "event",
    "events", "possible", "potential", "rule", "suspicious", "the",
    "using", "with",
}


def _raw_events_support_rule_title(
    rule_title: str,
    events: list[dict],
) -> bool:
    """Reject broad-query matches with no lexical support in raw evidence."""
    terms = {
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9_.-]+", str(rule_title))
        if len(token) >= 4
        and token.casefold() not in _RULE_RELEVANCE_STOPWORDS
    }
    if not terms or not events:
        return True
    evidence = json.dumps(events, ensure_ascii=False, default=str).casefold()
    return any(
        re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", evidence)
        for term in terms
    )


def _detection_candidates(detections: list[dict]) -> list[dict]:
    candidates = []
    for detection in detections:
        matched = int(detection.get("events_matched") or 0)
        if matched <= 0:
            continue
        run_id = str(detection.get("run_id") or "")
        event_cap = max(1, min(
            int(get_value(
                "autonomy", "risk_detection_event_cap", default=4
            )),
            20,
        ))
        compact_events = []
        for index, raw in enumerate(
            (detection.get("matched_events") or [])[:event_cap]
        ):
            if not isinstance(raw, dict):
                compact_events.append({
                    "record_ref": str(index),
                    "detail": str(raw)[:800],
                })
                continue
            compact_events.append({
                key: value
                for key, value in {
                    "record_ref": str(
                        raw.get("record_ref")
                        or raw.get("_record_ref")
                        or index
                    ),
                    "timestamp": raw.get("timestamp"),
                    "host": raw.get("host"),
                    "user": raw.get("user"),
                    "event": raw.get("event"),
                    "src_ip": raw.get("src_ip"),
                    "dst_ip": raw.get("dst_ip"),
                    "source_file": raw.get("source_file"),
                    "detail": str(raw.get("detail") or "")[:800],
                }.items()
                if value not in (None, "")
            })
        raw_analysis = (
            detection.get("analysis")
            if isinstance(detection.get("analysis"), dict)
            else {}
        )
        # Risk decisions must be based on persisted raw matches. Detection
        # triage and previous AI analysis are useful in their own workflow but
        # can repeat the rule title even when a broad query returned unrelated
        # records. Only objective execution metadata is carried forward here.
        objective_analysis = {
            key: raw_analysis.get(key)
            for key in (
                "method", "total_hits", "duration_ms", "generated_at",
                "deduplication", "first_event_at", "last_event_at",
                "distinct_hosts", "distinct_users", "top_hosts",
                "top_users", "top_event_types", "multi_search_requests",
            )
            if raw_analysis.get(key) not in (None, "", [], {})
        }
        explicit_rule_title = str(detection.get("rule_title") or "").strip()
        rule_title = str(
            explicit_rule_title or detection.get("rule_id") or "Detection"
        )
        if (
            explicit_rule_title
            and not _raw_events_support_rule_title(
                explicit_rule_title, compact_events
            )
        ):
            continue
        candidates.append({
            "candidate_id": f"detection:{run_id}",
            "source_type": "detection",
            "source_id": str(detection.get("rule_id") or ""),
            "source_label": rule_title,
            "detection_run_id": run_id,
            "events_matched": matched,
            "rule_metadata": {
                key: detection.get(key)
                for key in ("rule_id", "rule_title", "level", "siem_type")
            },
            "analysis": objective_analysis,
            "matched_events": compact_events,
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


async def _eligibility_decision(
    candidate: dict,
    *,
    agent: str = "risk_analysis",
) -> dict:
    candidate_id = str(candidate["candidate_id"])

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload.get("actionable"), bool):
            raise ValueError("eligibility decision must be boolean")
        rationale = str(payload.get("rationale") or "").strip()
        if not rationale:
            raise ValueError("eligibility rationale is required")
        return {
            "candidate_id": candidate_id,
            "actionable": payload["actionable"],
            "rationale": rationale[:300],
        }

    return await decide_json(
        agent=agent,
        system=ELIGIBILITY_SYSTEM_PROMPT,
        prompt="Validated candidate:\n" + json.dumps(
            candidate, separators=(",", ":"), ensure_ascii=False, default=str
        ),
        schema=RISK_ELIGIBILITY_SCHEMA,
        validator=validate,
        attempts=max(1, min(
            int(get_value("autonomy", "risk_analysis_attempts", default=2)),
            3,
        )),
        num_predict=256,
        transport_retries=0,
        timeout_seconds=max(30, min(
            float(get_value(
                "autonomy", "risk_analysis_timeout_seconds", default=180
            )),
            600,
        )),
    )


async def _analyze_batch(candidates: list[dict]) -> dict:
    eligible: list[dict] = []
    eligibility_excluded: list[str] = []
    for candidate in candidates:
        decision = await _eligibility_decision(candidate)
        if decision["actionable"]:
            eligible.append({
                **candidate,
                "eligibility_rationale": decision["rationale"],
            })
        else:
            eligibility_excluded.append(str(candidate["candidate_id"]))
    if not eligible:
        return {
            "items": [],
            "excluded_candidates": eligibility_excluded,
        }

    by_id = {str(item["candidate_id"]): item for item in eligible}
    single_candidate_id = next(iter(by_id)) if len(by_id) == 1 else ""
    rendered = {
        candidate_id: json.dumps(candidate, ensure_ascii=False, default=str)
        for candidate_id, candidate in by_id.items()
    }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        normalized = []
        seen = set()
        for item in payload.get("items") or []:
            # Detail decisions are intentionally one candidate at a time in
            # the production profile. Associate transport metadata in code so
            # the model spends its budget on the security decision rather
            # than copying a long opaque ID and citation array.
            candidate_id = single_candidate_id or str(
                item.get("candidate_id") or ""
            )
            candidate = by_id.get(candidate_id)
            if not candidate or candidate_id in seen:
                continue
            evidence_refs = (
                [single_candidate_id]
                if single_candidate_id
                else list(dict.fromkeys(
                    str(value) for value in item.get("evidence_refs") or []
                ))
            )
            if not evidence_refs or any(ref not in by_id for ref in evidence_refs):
                raise ValueError(
                    f"{candidate_id} must cite one or more supplied candidate IDs"
                )
            entity_name = str(item.get("entity_name") or "").strip()
            if not entity_name or entity_name.casefold() not in rendered[
                candidate_id
            ].casefold():
                raise ValueError(
                    f"{candidate_id} entity_name must be copied literally from its candidate"
                )
            try:
                score = int(item.get("score"))
            except (TypeError, ValueError):
                raise ValueError(f"{candidate_id} score must be an integer")
            if not 1 <= score <= 100:
                raise ValueError(f"{candidate_id} score must be between 1 and 100")
            expected_severity = (
                "critical" if score >= 90
                else "high" if score >= 70
                else "medium" if score >= 40
                else "low"
            )
            text_fields = {
                field: str(item.get(field) or "").strip()
                for field in (
                    "name", "description", "what", "why", "discovery",
                    "entity_type",
                )
            }
            if not all(text_fields.values()):
                missing = sorted(
                    field for field, value in text_fields.items() if not value
                )
                raise ValueError(
                    f"{candidate_id} requires non-empty fields: {', '.join(missing)}"
                )
            normalized.append({
                **item,
                "candidate_id": candidate_id,
                "name": text_fields["name"][:180],
                "description": text_fields["description"][:600],
                "what": text_fields["what"][:400],
                "why": text_fields["why"][:400],
                "discovery": text_fields["discovery"][:400],
                "entity_type": text_fields["entity_type"][:120],
                "entity_name": entity_name[:500],
                "score": score,
                # Severity is the governed presentation of the model-owned
                # impact score; deriving the band here prevents internally
                # contradictory risk cards without changing the verdict.
                "severity": expected_severity,
                "evidence_refs": evidence_refs,
            })
            seen.add(candidate_id)
        excluded = list(dict.fromkeys(
            str(value)
            for value in payload.get("excluded_candidates") or []
            if str(value) in by_id
        ))
        overlap = seen.intersection(excluded)
        if overlap:
            raise ValueError(
                "candidate cannot be both actionable and excluded: "
                + ", ".join(sorted(overlap))
            )
        unresolved = set(by_id).difference(seen).difference(excluded)
        if unresolved:
            raise ValueError(
                "decision omitted candidate(s): "
                + ", ".join(sorted(unresolved))
            )
        return {
            "items": normalized,
            "excluded_candidates": [*eligibility_excluded, *excluded],
        }

    decision_options = {
        "agent": "risk_analysis",
        "system": SYSTEM_PROMPT,
        "prompt": (
            "Validated risk candidates:\n"
            f"{json.dumps(eligible, separators=(',', ':'), default=str)}"
        ),
        "schema": RISK_SCHEMA,
        "validator": validate,
        "attempts": max(1, min(
            int(get_value("autonomy", "risk_analysis_attempts", default=1)),
            3,
        )),
        "num_predict": max(512, min(
            int(get_value("autonomy", "risk_analysis_num_predict", default=1600)),
            4096,
        )),
        "transport_retries": 0,
        "timeout_seconds": max(30, min(
            float(get_value(
                "autonomy", "risk_analysis_timeout_seconds", default=180
            )),
            600,
        )),
    }

    async def independently_review(result: dict) -> dict:
        approved_items = []
        rejected_ids = []

        def validate_review(payload: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(payload.get("approved"), bool):
                raise ValueError("review approved must be a boolean")
            rationale = str(payload.get("rationale") or "").strip()
            if not rationale:
                raise ValueError("review rationale is required")
            return {
                "approved": payload["approved"],
                "rationale": rationale[:300],
            }

        for item in result.get("items") or []:
            candidate_id = str(item.get("candidate_id") or "")
            candidate = by_id[candidate_id]
            review = await decide_json(
                agent="risk_reconsideration",
                system=RISK_REVIEW_SYSTEM_PROMPT,
                prompt=json.dumps({
                    "candidate": candidate,
                    "proposed_risk": item,
                }, ensure_ascii=False, separators=(",", ":"), default=str),
                schema=RISK_REVIEW_SCHEMA,
                validator=validate_review,
                attempts=1,
                num_predict=256,
                transport_retries=0,
                timeout_seconds=max(30, min(
                    float(get_value(
                        "autonomy", "risk_analysis_timeout_seconds", default=180
                    )),
                    600,
                )),
            )
            if review["approved"]:
                approved_items.append(item)
            else:
                rejected_ids.append(candidate_id)
        return {
            "items": approved_items,
            "excluded_candidates": list(dict.fromkeys([
                *(result.get("excluded_candidates") or []),
                *rejected_ids,
            ])),
        }

    try:
        detailed_result = await decide_json(**decision_options)
    except AgentDecisionError as detail_error:
        if len(eligible) != 1:
            raise
        try:
            detailed_result = await decide_json(**{
                **decision_options,
                "agent": "risk_reconsideration",
                "prompt": (
                    decision_options["prompt"]
                    + "\n\nThe fast-tier detail writer failed deterministic "
                    "validation. Produce one corrected risk object using a "
                    "literal entity from the supplied candidate. Validation "
                    f"failure: {str(detail_error)[:1000]}"
                ),
                "attempts": 1,
                "num_predict": 1024,
            })
        except AgentDecisionError as recovery_error:
            combined_failure = (
                f"fast detail: {detail_error}; cybersecurity-tier detail: "
                f"{recovery_error}"
            )
            candidate = {
                **eligible[0],
                "detail_validation_failure": combined_failure[:1600],
                "reconsideration_instruction": (
                    "Reconsider actionability because the detailed risk writer "
                    "could not ground a required entity or valid risk object."
                ),
            }
            reconsidered = await _eligibility_decision(
                candidate,
                agent="risk_reconsideration",
            )
            if not reconsidered["actionable"]:
                return {
                    "items": [],
                    "excluded_candidates": [str(candidate["candidate_id"])],
                }
            raise detail_error
    return await independently_review(detailed_result)


def risk_source_version(
    hunts: list[dict],
    detections: list[dict],
    reports_dir: str | Path,
) -> str:
    """Fingerprint persisted risk inputs without embedding their full contents."""
    reports_root = Path(reports_dir)
    material: list[dict[str, Any]] = [{
        "kind": "policy",
        "id": RISK_DECISION_POLICY_VERSION,
    }]
    for hunt in hunts:
        report_path = reports_root / Path(str(hunt.get("report_path") or "")).name
        try:
            stat = report_path.stat()
            report_state = [stat.st_size, stat.st_mtime_ns]
        except OSError:
            report_state = [0, 0]
        material.append({
            "kind": "hunt",
            "id": str(hunt.get("hunt_id") or ""),
            "status": str(hunt.get("status") or ""),
            "updated_at": str(hunt.get("updated_at") or ""),
            "report": report_state,
        })
    for detection in detections:
        material.append({
            "kind": "detection",
            "id": str(detection.get("run_id") or ""),
            "events": int(detection.get("events_matched") or 0),
            "created_at": str(detection.get("created_at") or ""),
            "analysis": hashlib.sha256(json.dumps(
                detection.get("analysis") or {},
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")).hexdigest()[:16],
            "matched_events": hashlib.sha256(json.dumps(
                detection.get("matched_events") or [],
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")).hexdigest()[:16],
        })
    encoded = json.dumps(
        sorted(material, key=lambda item: (item["kind"], item["id"])),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_batches(
    candidates: list[dict],
    item_cap: int,
    prompt_char_cap: int,
) -> list[list[dict]]:
    batches: list[list[dict]] = []
    current: list[dict] = []
    current_chars = 2
    for candidate in candidates:
        rendered_chars = len(json.dumps(
            candidate, separators=(",", ":"), default=str
        )) + 1
        if current and (
            len(current) >= item_cap
            or current_chars + rendered_chars > prompt_char_cap
        ):
            batches.append(current)
            current = []
            current_chars = 2
        current.append(candidate)
        current_chars += rendered_chars
    if current:
        batches.append(current)
    return batches


def _risk_summary(risks: list[dict]) -> dict:
    active_risks = [
        item for item in risks
        if item.get("active", str(item.get("status") or "open").lower() != "resolved")
    ]
    entities = {
        f"{item['entity']['type']}:{item['entity']['name']}" for item in active_risks
    }
    return {
        "total": len(active_risks),
        "inactive": len(risks) - len(active_risks),
        "critical": sum(item["severity"] == "critical" for item in active_risks),
        "high": sum(item["severity"] == "high" for item in active_risks),
        "medium": sum(item["severity"] == "medium" for item in active_risks),
        "low": sum(item["severity"] == "low" for item in active_risks),
        "affected_entities": len(entities),
        "average_score": round(
            sum(item["score"] for item in active_risks) / len(active_risks), 1
        ) if active_risks else 0,
        "report_findings": sum(
            item["source_type"] == "hunt_report" for item in active_risks
        ),
        "detection_findings": sum(
            item["source_type"] == "detection" for item in active_risks
        ),
    }


def apply_risk_resolutions(payload: dict, resolutions: list[dict]) -> dict:
    """Overlay durable analyst decisions without modifying model evidence."""
    resolved_by_id = {
        str(item.get("risk_id") or ""): item
        for item in resolutions
        if isinstance(item, dict) and item.get("risk_id")
    }
    items = []
    for source in payload.get("items") or []:
        if not isinstance(source, dict):
            continue
        item = dict(source)
        resolution = resolved_by_id.get(str(item.get("id") or ""))
        if resolution and str(resolution.get("status") or "").lower() == "resolved":
            item.update({
                "status": "resolved",
                "active": False,
                "resolved_by": resolution.get("resolved_by"),
                "resolved_at": resolution.get("resolved_at"),
                "resolution_note": resolution.get("note") or "",
            })
        else:
            item.update({"status": "open", "active": True})
        items.append(item)
    return {**payload, "items": items}


def filter_risk_payload(
    payload: dict,
    limit: int = 500,
    hours: int | None = None,
) -> dict:
    """Apply view bounds to a materialized snapshot without model inference."""
    risks = [item for item in payload.get("items") or [] if isinstance(item, dict)]
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=max(1, min(int(hours), 24 * 365 * 10))
        )
        retained = []
        for item in risks:
            try:
                identified = datetime.fromisoformat(
                    str(item.get("identified_at") or "").replace("Z", "+00:00")
                )
                if identified.tzinfo is None:
                    identified = identified.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if identified >= cutoff:
                retained.append(item)
        risks = retained
    risks = risks[:max(1, min(int(limit), 2000))]
    summary = _risk_summary(risks)
    candidate_count = len(payload.get("_candidate_fingerprints") or {})
    excluded_count = len(payload.get("_excluded_candidate_ids") or [])
    summary.update({
        "reviewed_candidates": candidate_count or len(risks) + excluded_count,
        "excluded_candidates": excluded_count,
    })
    return {**payload, "summary": summary, "items": risks}


async def analyze_actionable_risks(
    hunts: list[dict],
    detections: list[dict],
    reports_dir: str | Path,
    limit: int = 500,
    hours: int | None = None,
    previous_payload: dict | None = None,
) -> dict:
    """Return risks selected and explained by the Risk Analysis Agent.

    Candidate decisions are reused only when the complete normalized source
    candidate is byte-for-byte equivalent to the version previously analyzed.
    This keeps report-triggered refreshes incremental without encoding any
    vendor, technique, event-ID, or verdict logic in Python.
    """
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
    candidates.sort(
        key=lambda item: str(item.get("identified_at") or ""),
        reverse=True,
    )
    candidate_cap = max(
        1,
        min(
            int(get_value("autonomy", "risk_candidate_cap", default=16)),
            500,
        ),
    )
    candidates = candidates[:candidate_cap]
    candidate_by_id = {
        str(item["candidate_id"]): item for item in candidates
    }
    candidate_fingerprints = {
        candidate_id: hashlib.sha256(json.dumps(
            candidate,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")).hexdigest()
        for candidate_id, candidate in candidate_by_id.items()
    }
    previous = previous_payload if isinstance(previous_payload, dict) else {}
    if previous.get("_decision_policy_version") != RISK_DECISION_POLICY_VERSION:
        previous = {}
    previous_fingerprints = (
        previous.get("_candidate_fingerprints")
        if isinstance(previous.get("_candidate_fingerprints"), dict)
        else {}
    )
    unchanged_ids = {
        candidate_id
        for candidate_id, fingerprint in candidate_fingerprints.items()
        if previous_fingerprints.get(candidate_id) == fingerprint
    }
    preserved_risks = []
    preserved_actionable_ids = set()
    for item in previous.get("items") or []:
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("candidate_id") or "")
        evidence_refs = {
            str(value) for value in item.get("evidence_refs") or []
        }
        if (
            candidate_id in unchanged_ids
            and evidence_refs
            and evidence_refs.issubset(unchanged_ids)
        ):
            preserved_risks.append(dict(item))
            preserved_actionable_ids.add(candidate_id)
    previous_excluded = {
        str(value) for value in previous.get("_excluded_candidate_ids") or []
    }
    preserved_excluded_ids = previous_excluded.intersection(unchanged_ids)
    cached_ids = preserved_actionable_ids.union(preserved_excluded_ids)
    pending_candidates = [
        candidate
        for candidate in candidates
        if str(candidate["candidate_id"]) not in cached_ids
    ]
    batch_size = max(
        1,
        min(
            int(get_value("autonomy", "risk_batch_size", default=12)),
            100,
        ),
    )
    prompt_char_cap = max(8000, min(
        int(get_value("autonomy", "risk_prompt_char_cap", default=70000)),
        120_000,
    ))
    batches = _candidate_batches(
        pending_candidates, batch_size, prompt_char_cap
    )
    concurrency = max(1, min(
        len(batches) or 1,
        internal_worker_limit(
            "risk", int(get_value("autonomy", "risk_batch_concurrency", default=2)),
        ),
        4,
    ))
    semaphore = asyncio.Semaphore(concurrency)

    async def analyze_batch(
        batch: list[dict],
    ) -> tuple[list[dict], list[str]]:
        """Analyze a compact batch, then isolate only an oversized failure.

        Small local models can occasionally exhaust their output budget when
        two otherwise-valid candidates both need detailed explanations. A
        failed multi-candidate response is retried as independent candidate
        decisions; this is model-owned recovery and does not substitute a
        deterministic security verdict.
        """
        async with semaphore:
            try:
                return [await _analyze_batch(batch)], []
            except AgentDecisionError as exc:
                if len(batch) <= 1:
                    return [], [str(exc)]
                results: list[dict] = []
                errors: list[str] = []
                for candidate in batch:
                    try:
                        results.append(await _analyze_batch([candidate]))
                    except AgentDecisionError as candidate_exc:
                        errors.append(str(candidate_exc))
                return results, errors

    batch_results = await asyncio.gather(*(
        analyze_batch(batch) for batch in batches
    ))
    successful_results = [
        result
        for results, _errors in batch_results
        for result in results
    ]
    model_items = [
        item
        for result in successful_results
        for item in result.get("items") or []
    ]
    failures = [
        error
        for _results, errors in batch_results
        for error in errors
    ]
    newly_excluded_ids = {
        str(candidate_id)
        for result in successful_results
        for candidate_id in result.get("excluded_candidates") or []
        if str(candidate_id) in candidate_by_id
    }
    risks = preserved_risks
    new_actionable_ids = set()
    for item in model_items:
        candidate = candidate_by_id[item["candidate_id"]]
        new_actionable_ids.add(item["candidate_id"])
        risks.append({
            "id": _risk_id(item, candidate),
            "candidate_id": item["candidate_id"],
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
    summary = _risk_summary(risks)
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
        "_decision_policy_version": RISK_DECISION_POLICY_VERSION,
        "_candidate_fingerprints": candidate_fingerprints,
        "_excluded_candidate_ids": sorted(
            preserved_excluded_ids.union(
                newly_excluded_ids - new_actionable_ids
            )
        ),
    }
