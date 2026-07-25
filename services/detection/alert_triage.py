"""Deterministic scheduled-detection triage.

This agent deliberately avoids an LLM call. Sigma metadata, match counts, and
the local MITRE table are enough to produce a short, auditable first-pass note
without spending GPU memory or adding latency to every hourly rule execution.
"""
from __future__ import annotations

import re

from services.knowledge import mitre


_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_PRIORITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _technique_id(tags: list[str]) -> str:
    for tag in tags:
        match = _TECHNIQUE.match(str(tag))
        if match:
            return match.group(1).upper()
    return ""


def triage_detection(result: dict) -> dict:
    """Build a compact enrichment note and case priority from trusted metadata."""
    tags = [str(tag) for tag in (result.get("tags") or [])]
    technique_id = _technique_id(tags)
    technique = mitre.map_technique(technique_id) if technique_id else None
    count = int(result.get("events_matched", 0))
    level = str(result.get("level") or "medium").lower()
    priority = _PRIORITY.get(level, "medium")
    title = str(result.get("rule_title") or result.get("rule_id") or "Scheduled detection")
    context = (
        f" MITRE {technique_id} ({technique.get('name', 'unknown technique')})"
        if technique_id and technique
        else (f" MITRE {technique_id}" if technique_id else "")
    )
    note = (
        f"{title} produced {count} new, deduplicated match(es) in "
        f"{result.get('siem_type', 'the active SIEM')}.{context}"
    )
    action = (
        "Validate the matched records, affected identities, and host timeline before containment."
        if priority in {"high", "critical"}
        else "Review the matched records and correlate them with recent activity before closing."
    )
    return {
        "priority": priority,
        "technique_id": technique_id,
        "technique_name": technique.get("name") if technique else None,
        "tactic": technique.get("tactic") if technique else None,
        "note": note,
        "recommended_action": action,
        "method": "deterministic_sigma_metadata",
    }
