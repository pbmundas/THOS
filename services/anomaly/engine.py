"""Deterministic, explainable anomaly detection over normalized telemetry.

The model does not decide whether a value is rare or abnormal. This module
builds entity metrics, compares them with persisted historical buckets, and
emits leads containing the measured baseline and exact contributing records.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import math
from statistics import median
from typing import Any


ENTITY_FIELDS = (("user", "user"), ("host", "host"), ("ip", "src_ip"))
EMPTY_ENTITIES = {"", "-", "none", "null", "unknown", "n/a"}


def _clean(value: Any, limit: int = 240) -> str:
    text = " ".join(str(value or "").strip().split())
    return text[:limit]


def _category(record: dict[str, Any]) -> str:
    return _clean(
        record.get("event_category")
        or record.get("event")
        or record.get("event_dataset")
        or "activity",
        120,
    ).lower()


def _evidence_record(index: int, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_index": index,
        "timestamp": _clean(record.get("timestamp"), 80),
        "host": _clean(record.get("host")),
        "user": _clean(record.get("user")),
        "event": _clean(record.get("event"), 160),
        "src_ip": _clean(record.get("src_ip"), 80),
        "dst_ip": _clean(record.get("dst_ip"), 80),
        "detail": _clean(record.get("detail"), 800),
        "source_type": _clean(record.get("source_type"), 80),
    }


def build_observations(
    records: list[dict[str, Any]], source: str, bucket_start: datetime,
) -> list[dict[str, Any]]:
    """Aggregate one evaluation window into entity and relationship metrics."""
    counters: Counter[tuple[str, str, str, str]] = Counter()
    evidence: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        category = _category(record)
        entities: list[tuple[str, str]] = []
        for entity_type, field in ENTITY_FIELDS:
            entity_name = _clean(record.get(field))
            if entity_name.casefold() not in EMPTY_ENTITIES:
                entities.append((entity_type, entity_name))
        for entity_type, entity_name in entities:
            key = ("entity_activity_spike", entity_type, entity_name, category)
            counters[key] += 1
            if len(evidence[key]) < 5:
                evidence[key].append(_evidence_record(index, record))

        user = _clean(record.get("user"))
        host = _clean(record.get("host"))
        if user.casefold() not in EMPTY_ENTITIES and host.casefold() not in EMPTY_ENTITIES:
            key = ("new_user_host_relationship", "user", user, f"host:{host}")
            counters[key] += 1
            if len(evidence[key]) < 5:
                evidence[key].append(_evidence_record(index, record))

    return [
        {
            "source": _clean(source, 80).lower(),
            "bucket_start": bucket_start.astimezone(timezone.utc),
            "detector_id": detector_id,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "metric": metric,
            "value": float(value),
            "evidence": evidence[(detector_id, entity_type, entity_name, metric)],
        }
        for (detector_id, entity_type, entity_name, metric), value in sorted(counters.items())
    ]


def _robust_score(observed: float, values: list[float]) -> tuple[float, float, float]:
    expected = float(median(values)) if values else 0.0
    deviations = [abs(value - expected) for value in values]
    mad = float(median(deviations)) if deviations else 0.0
    if mad > 0:
        score = 0.6745 * (observed - expected) / mad
    elif expected > 0:
        score = (observed / expected) - 1.0
    else:
        score = observed
    return expected, mad, round(max(0.0, score), 3)


def _lead_id(source: str, detector: str, entity_type: str, entity_name: str, metric: str) -> str:
    material = "|".join((source, detector, entity_type, entity_name.casefold(), metric.casefold()))
    return "ANOM-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20].upper()


def _severity(score: float) -> str:
    if score >= 10:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def evaluate_anomalies(
    observations: list[dict[str, Any]],
    history: list[dict[str, Any]],
    *,
    min_baseline_buckets: int = 24,
    spike_threshold: float = 4.0,
    minimum_observed: int = 5,
    relationship_minimum_observed: int = 2,
) -> list[dict[str, Any]]:
    """Return statistically supported leads from current and prior buckets."""
    history_by_key: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    entity_buckets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in history:
        key = (
            _clean(row.get("detector_id")),
            _clean(row.get("entity_type")),
            _clean(row.get("entity_name")),
            _clean(row.get("metric")),
        )
        try:
            history_by_key[key].append(float(row.get("value") or 0))
        except (TypeError, ValueError):
            continue
        entity_buckets[(key[0], key[1], key[2])].add(str(row.get("bucket_start") or ""))

    leads: list[dict[str, Any]] = []
    for current in observations:
        detector = _clean(current.get("detector_id"))
        entity_type = _clean(current.get("entity_type"))
        entity_name = _clean(current.get("entity_name"))
        metric = _clean(current.get("metric"))
        source = _clean(current.get("source"), 80).lower()
        observed = float(current.get("value") or 0)
        key = (detector, entity_type, entity_name, metric)
        values = history_by_key.get(key, [])
        baseline_bucket_count = len(values)
        entity_history_count = len(entity_buckets.get((detector, entity_type, entity_name), set()))

        expected = mad = score = 0.0
        reason = title = ""
        qualifies = False
        if detector == "entity_activity_spike":
            if baseline_bucket_count >= min_baseline_buckets and observed >= minimum_observed:
                expected, mad, score = _robust_score(observed, values)
                qualifies = score >= spike_threshold and observed >= max(
                    minimum_observed, math.ceil(expected * 2)
                )
                title = f"Activity spike for {entity_type} {entity_name}"
                reason = (
                    f"Observed {observed:g} `{metric}` events versus a historical "
                    f"median of {expected:g} across {baseline_bucket_count} comparable buckets."
                )
        elif detector == "new_user_host_relationship":
            if entity_history_count >= min_baseline_buckets and not values \
                    and observed >= relationship_minimum_observed:
                expected, mad, score = 0.0, 0.0, max(4.0, observed + 2.0)
                host = metric.removeprefix("host:")
                qualifies = True
                title = f"New user-to-host relationship: {entity_name} → {host}"
                reason = (
                    f"User `{entity_name}` was observed on `{host}` {observed:g} time(s), "
                    f"but this relationship was absent from {entity_history_count} prior buckets."
                )
        if not qualifies:
            continue

        lead_id = _lead_id(source, detector, entity_type, entity_name, metric)
        hypothesis = (
            f"Investigate anomaly lead {lead_id}. {reason} Determine whether the activity "
            "is authorized or security-relevant. Retrieve the contributing entity's activity, "
            "cite exact records, consider benign operational explanations, and do not treat "
            "statistical rarity as proof of compromise."
        )
        leads.append({
            "lead_id": lead_id,
            "source": source,
            "detector_id": detector,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "metric": metric,
            "title": title,
            "reason": reason,
            "observed": observed,
            "expected": expected,
            "score": score,
            "severity": _severity(score),
            "baseline": {
                "bucket_count": baseline_bucket_count,
                "entity_bucket_count": entity_history_count,
                "median": expected,
                "mad": mad,
                "minimum_required_buckets": min_baseline_buckets,
                "method": "median_mad" if detector == "entity_activity_spike" else "new_edge",
            },
            "evidence": list(current.get("evidence") or [])[:5],
            "hypothesis_text": hypothesis,
        })
    return sorted(leads, key=lambda item: (-float(item["score"]), item["lead_id"]))
