"""Vendor-neutral impact classification for canonical hunt hypotheses."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Iterable


POLICY_PATH = (
    Path(__file__).resolve().parent / "data" / "hypothesis_severity_policy.json"
)
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _load_policy() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


POLICY = _load_policy()


def _values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _unique(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value).strip()
        key = candidate.casefold()
        if candidate and key not in seen:
            seen.add(key)
            output.append(candidate)
    return output


def _known_tactics(
    item: dict[str, Any],
    mapped_tactics: Iterable[str],
) -> list[str]:
    configured = list(POLICY.get("tactic_scores", {}))
    candidates = _unique([
        *_values(item.get("tactic")),
        *_values(item.get("all_tactics")),
        *mapped_tactics,
    ])
    matched = []
    for candidate in candidates:
        normalized = re.sub(r"\s*\([^)]*\)\s*$", "", candidate).strip()
        for tactic in configured:
            if normalized.casefold() == tactic.casefold():
                matched.append(tactic)
                break
    return _unique(matched)


def _severity_for_score(score: int) -> str:
    thresholds = POLICY.get("severity_thresholds", {})
    ranked = sorted(
        (
            (str(severity).lower(), int(threshold))
            for severity, threshold in thresholds.items()
            if str(severity).lower() in VALID_SEVERITIES
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    return next(
        (severity for severity, threshold in ranked if score >= threshold),
        "low",
    )


def classify_hypothesis_impact(
    item: dict[str, Any],
    *,
    technique_names: Iterable[str] = (),
    mapped_tactics: Iterable[str] = (),
) -> dict[str, Any]:
    """Classify impact assuming the hunt produced a validated finding.

    The policy is independent of SIEM vendors, telemetry fields, and
    hypothesis IDs. Actual incident priority still requires the contextual
    review parameters returned with the classification.
    """
    tactics = _known_tactics(item, mapped_tactics)
    tactic_scores = POLICY.get("tactic_scores", {})
    base_score = max(
        (
            int(tactic_scores.get(tactic, POLICY["default_tactic_score"]))
            for tactic in tactics
        ),
        default=int(POLICY["default_tactic_score"]),
    )
    text = " ".join([
        str(item.get("title") or ""),
        str(item.get("text") or ""),
        " ".join(_values(item.get("tags"))),
        " ".join(technique_names),
        " ".join(tactics),
    ]).casefold()

    factors: list[dict[str, Any]] = []
    domains = _unique(
        domain
        for tactic in tactics
        for domain in POLICY.get("tactic_impact_domains", {}).get(tactic, [])
    )
    score = base_score
    for signal in POLICY.get("consequence_signals", []):
        if re.search(
            str(signal.get("pattern") or r"(?!x)x"),
            text,
            re.IGNORECASE,
        ):
            points = max(0, int(signal.get("points") or 0))
            score += points
            factors.append({
                "name": str(signal.get("name") or "impact consequence"),
                "points": points,
            })
            domains = _unique([
                *domains,
                *_values(signal.get("impact_domains")),
            ])

    score = min(100, max(0, score))
    severity = _severity_for_score(score)
    assets = _unique(
        str(asset.get("name"))
        for asset in POLICY.get("asset_classes", [])
        if re.search(
            str(asset.get("pattern") or r"(?!x)x"),
            text,
            re.IGNORECASE,
        )
    )
    factor_names = [factor["name"] for factor in factors]
    rationale = (
        f"{severity.title()} potential impact (score {score}/100) assuming a "
        "validated positive finding. "
        f"Base consequence is derived from "
        f"{', '.join(tactics) or 'unmapped tactic'}"
        + (
            f"; elevated by {', '.join(factor_names)}."
            if factor_names
            else "."
        )
    )
    return {
        "severity": severity,
        "severity_score": score,
        "severity_rationale": rationale,
        "risk_parameters": {
            "policy_version": str(POLICY.get("version") or ""),
            "classification_basis": str(POLICY.get("assumption") or ""),
            "tactics": tactics,
            "tactic_base_score": base_score,
            "consequence_factors": factors,
            "impact_domains": domains,
            "asset_classes": assets or ["environment-dependent"],
            "review_parameters": list(POLICY.get("review_parameters", [])),
            "vendor_agnostic": True,
        },
    }
