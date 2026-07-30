"""Canonical, vendor-neutral hypothesis catalog normalization."""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from services.hunting.hypothesis_severity import (
    VALID_SEVERITIES,
    classify_hypothesis_impact,
)
from services.knowledge.mitre import map_technique


CANONICAL_HYPOTHESIS_ID = re.compile(r"^[BHM]-?\d+$", re.IGNORECASE)
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return []
        if candidate.startswith("["):
            try:
                decoded = json.loads(candidate)
            except ValueError:
                decoded = None
            if isinstance(decoded, list):
                return [
                    str(item).strip()
                    for item in decoded
                    if str(item).strip()
                ]
        return [candidate]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _unique(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value).strip()
        key = normalized.casefold()
        if normalized and key not in seen:
            seen.add(key)
            output.append(normalized)
    return output


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            decoded = json.loads(value)
        except ValueError:
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def is_canonical_hypothesis_id(value: Any) -> bool:
    return bool(CANONICAL_HYPOTHESIS_ID.fullmatch(str(value or "").strip()))


def _technique_ids(item: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for field in ("technique", "techniques", "all_techniques"):
        candidates.extend(_values(item.get(field)))
    for field in ("tactic", "all_tactics", "tags"):
        for value in _values(item.get(field)):
            candidates.extend(TECHNIQUE_ID.findall(value))

    return _unique(
        match.upper()
        for candidate in candidates
        for match in TECHNIQUE_ID.findall(candidate)
    )


def normalize_hypothesis(item: dict[str, Any]) -> dict[str, Any]:
    """Attach searchable ATT&CK IDs/names without adding SIEM assumptions."""
    normalized = dict(item)
    technique_ids = _technique_ids(item)
    technique_names = _unique([
        *_values(item.get("technique_names")),
        *(
            str(
                (map_technique(technique_id) or {}).get("name")
                or ""
            ).strip()
            for technique_id in technique_ids
        ),
    ])
    if not technique_names:
        technique_names = ["Unmapped ATT&CK technique"]

    tactic = str(item.get("tactic") or "").strip()
    if technique_ids and ("(" in tactic or not tactic):
        mapped_tactic = str(
            (map_technique(technique_ids[0]) or {}).get("tactic") or ""
        ).strip()
        tactic = mapped_tactic or tactic

    mapped_tactics = _unique(
        str((map_technique(technique_id) or {}).get("tactic") or "").strip()
        for technique_id in technique_ids
    )
    impact = classify_hypothesis_impact(
        {**item, "tactic": tactic},
        technique_names=technique_names,
        mapped_tactics=mapped_tactics,
    )
    existing_risk = _mapping(item.get("risk_parameters"))
    explicit_severity = str(item.get("severity") or "").strip().lower()
    policy_derived = (
        existing_risk.get("policy_version")
        == impact["risk_parameters"].get("policy_version")
    )
    if explicit_severity in VALID_SEVERITIES and (
        not is_canonical_hypothesis_id(item.get("id"))
        or policy_derived
    ):
        impact["severity"] = explicit_severity
        if not policy_derived:
            impact["risk_parameters"]["classification_basis"] = (
                "Authored severity; contextual review parameters still apply."
            )
    if existing_risk:
        impact["risk_parameters"] = existing_risk
        try:
            impact["severity_score"] = max(
                0,
                min(100, int(item.get("severity_score"))),
            )
        except (TypeError, ValueError):
            pass
        existing_rationale = str(
            item.get("severity_rationale") or ""
        ).strip()
        if existing_rationale:
            impact["severity_rationale"] = existing_rationale

    tags = _unique([
        *technique_ids,
        *technique_names,
        *_values(item.get("tags")),
        "vendor-agnostic",
    ])
    normalized.update({
        "id": str(item.get("id") or "").strip(),
        "title": str(item.get("title") or "").strip(),
        "text": str(item.get("text") or "").strip(),
        "tactic": tactic,
        "technique": (
            str(item.get("technique") or "").strip()
            or (technique_ids[0] if technique_ids else "")
        ),
        "techniques": technique_ids,
        "technique_names": technique_names,
        "tags": tags,
        "vendor_agnostic": True,
        **impact,
    })
    return normalized


def canonical_hypotheses(
    items: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return only the established B/H/M catalog, de-duplicated and sorted."""
    canonical = {
        str(item.get("id")): normalize_hypothesis(item)
        for item in items
        if isinstance(item, dict) and is_canonical_hypothesis_id(item.get("id"))
    }
    return sorted(canonical.values(), key=lambda item: str(item["id"]))


def hypothesis_document(item: dict[str, Any]) -> str:
    normalized = normalize_hypothesis(item)
    return " ".join(filter(None, [
        normalized["title"],
        normalized["text"],
        f"ATT&CK tactic: {normalized['tactic']}.",
        f"ATT&CK technique IDs: {', '.join(normalized['techniques'])}.",
        f"ATT&CK technique names: {', '.join(normalized['technique_names'])}.",
        f"Impact severity: {normalized['severity']}.",
        f"Impact score: {normalized['severity_score']}.",
        normalized["severity_rationale"],
        " ".join(normalized["risk_parameters"].get("impact_domains", [])),
        " ".join(normalized["risk_parameters"].get("asset_classes", [])),
        f"Tags: {', '.join(normalized['tags'])}.",
    ]))


def hypothesis_metadata(item: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_hypothesis(item)
    return {
        "id": normalized["id"],
        "title": normalized["title"],
        "tactic": normalized["tactic"],
        "technique": normalized["technique"],
        "text": normalized["text"],
        "severity": str(normalized.get("severity") or ""),
        "severity_score": int(normalized.get("severity_score") or 0),
        "severity_rationale": str(
            normalized.get("severity_rationale") or ""
        ),
        "risk_parameters": json.dumps(
            normalized.get("risk_parameters") or {},
            ensure_ascii=False,
            sort_keys=True,
        ),
        "category": str(normalized.get("category") or ""),
        "all_tactics": json.dumps(
            _unique([
                *_values(normalized.get("all_tactics")),
                normalized.get("tactic", ""),
            ]),
            ensure_ascii=False,
        ),
        "techniques": json.dumps(normalized["techniques"], ensure_ascii=False),
        "technique_names": json.dumps(
            normalized["technique_names"], ensure_ascii=False
        ),
        "tags": json.dumps(normalized["tags"], ensure_ascii=False),
        "vendor_agnostic": True,
    }


def metadata_to_hypothesis(meta: dict[str, Any]) -> dict[str, Any]:
    return normalize_hypothesis({
        "id": meta.get("id", ""),
        "title": meta.get("title", ""),
        "tactic": meta.get("tactic", ""),
        "technique": meta.get("technique", ""),
        "text": meta.get("text", ""),
        "severity": meta.get("severity", ""),
        "severity_score": meta.get("severity_score", 0),
        "severity_rationale": meta.get("severity_rationale", ""),
        "risk_parameters": _mapping(meta.get("risk_parameters")),
        "category": meta.get("category", ""),
        "all_tactics": _values(meta.get("all_tactics")),
        "techniques": _values(meta.get("techniques")),
        "technique_names": _values(meta.get("technique_names")),
        "tags": _values(meta.get("tags")),
    })
