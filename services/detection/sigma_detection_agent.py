"""Sigma query execution for scheduled detections and hypothesis hunts."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

from services.detection import sigma_engine, sigmahq_engine
from services.detection.alert_triage import triage_detection
from services.detection.sigma_query_catalog import applicable_rules, find_rule
from services.mcp.mcp_client import call_tool
from services.observability import cache
from services.siem import wazuh as wazuh_connector
from services.siem.log_processing import process_logs_node


LOCAL_SOURCES = {"folder", "local_folder", "file", "local", "mock"}
EVENT_FIELDS = ("timestamp", "host", "user", "event", "src_ip", "dst_ip", "detail", "source_file")
RECURRING_HIT_NAMESPACE = "scheduled_detection_hits"


def _selected_local_rule(rule_id: str):
    local = next((rule for rule in sigma_engine.load_rules() if str(rule.get("id")) == rule_id), None)
    if local is not None:
        return "THOS", local
    community = next((rule for rule in sigmahq_engine.load_rules() if rule.rule_id == rule_id), None)
    if community is not None:
        return "Community", community
    raise LookupError(f"enabled detection rule {rule_id} was not found in the active corpus")


def _metadata(source: str, rule) -> dict:
    if source == "THOS":
        return {"rule_id": str(rule.get("id")), "rule_title": str(rule.get("title", "Untitled rule")),
                "level": str(rule.get("level", "medium")), "tags": list(rule.get("tags", []))}
    return {"rule_id": rule.rule_id, "rule_title": rule.title, "level": rule.level, "tags": list(rule.tags)}


def _event_view(record: dict, reference: int) -> dict:
    event = {field: record.get(field) for field in EVENT_FIELDS if record.get(field) not in (None, "")}
    event["record_ref"] = reference
    if isinstance(event.get("detail"), str) and len(event["detail"]) > 2_000:
        event["detail"] = event["detail"][:2_000] + "…"
    return event


def _analysis(events: list[dict], query_count: int, method: str) -> dict:
    hosts = Counter(str(item.get("host")) for item in events if item.get("host"))
    users = Counter(str(item.get("user")) for item in events if item.get("user"))
    event_types = Counter(str(item.get("event")) for item in events if item.get("event"))
    timestamps = sorted(str(item.get("timestamp")) for item in events if item.get("timestamp"))
    return {
        "summary": f"{len(events)} matching event(s) were returned by {query_count} targeted detection-rule query execution(s).",
        "distinct_hosts": len(hosts), "distinct_users": len(users),
        "top_hosts": [{"value": v, "count": c} for v, c in hosts.most_common(10)],
        "top_users": [{"value": v, "count": c} for v, c in users.most_common(10)],
        "top_event_types": [{"value": v, "count": c} for v, c in event_types.most_common(10)],
        "first_event_at": timestamps[0] if timestamps else None,
        "last_event_at": timestamps[-1] if timestamps else None,
        "generated_at": datetime.now(timezone.utc).isoformat(), "method": method,
    }


def _timestamp_bucket(value: object, window_seconds: int) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return str(int(parsed.timestamp()) // window_seconds)
    except (TypeError, ValueError):
        return str(value or "")


def event_fingerprint(event: dict, window_seconds: int = 3600) -> str:
    """Fingerprint one event without retaining sensitive values in Redis keys."""
    payload = {
        "host": event.get("host"),
        "user": event.get("user"),
        "event": event.get("event"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "source_file": event.get("source_file"),
        "timestamp_window": _timestamp_bucket(event.get("timestamp"), window_seconds),
        "detail_hash": hashlib.sha256(
            str(event.get("detail") or "").encode("utf-8", errors="replace")
        ).hexdigest()[:16],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def deduplicate_recurring_hits(
    rule_id: str,
    siem_type: str,
    current_hits: list[dict],
    *,
    schedule_id: str = "",
    window_seconds: int | None = None,
) -> tuple[list[dict], dict]:
    """Suppress events already returned by the previous scheduled execution."""
    window = max(
        60,
        int(window_seconds or os.environ.get("SIGMA_DEDUP_WINDOW_SECONDS", "3600")),
    )
    identity = f"{schedule_id}:{rule_id}:{siem_type}"
    previous = cache.cache_get(RECURRING_HIT_NAMESPACE, identity)
    previous_fingerprints = set(
        previous.get("fingerprints", [])
        if isinstance(previous, dict)
        else []
    )
    current = [(event_fingerprint(event, window), event) for event in current_hits]
    fresh = [event for fingerprint, event in current if fingerprint not in previous_fingerprints]
    cache.cache_set(
        RECURRING_HIT_NAMESPACE,
        identity,
        {
            "fingerprints": sorted({fingerprint for fingerprint, _event in current}),
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "window_seconds": window,
        },
        ttl=max(window * 3, 3600),
    )
    return fresh, {
        "raw_events_matched": len(current_hits),
        "new_events_matched": len(fresh),
        "duplicates_suppressed": len(current_hits) - len(fresh),
        "fingerprint_window_seconds": window,
    }


async def _execute(entry: dict, siem_type: str, limit: int) -> tuple[dict, dict]:
    result = await call_tool("fetch_siem_logs", {
        "query": entry["query"], "limit": limit, "siem_type": siem_type,
        "log_source_path": "", "trusted_sigma": True,
    })
    if result.get("error"):
        raise RuntimeError(f"{entry['rule_id']}: {result['error']}")
    return entry, result


async def query_sigma_for_hunt(*, siem_type: str, technique_id: str = "", tactic: str = "",
                               per_rule_limit: int | None = None) -> dict:
    """Execute only ATT&CK-relevant precompiled rules in the live SIEM."""
    entries, coverage = applicable_rules(siem_type, technique_id, tactic)
    execution_mode = "individual_search"
    if siem_type.lower() == "wazuh" and entries:
        try:
            batch_results = await asyncio.to_thread(
                wazuh_connector.fetch_multi_logs,
                [
                    {
                        "rule_id": entry["rule_id"],
                        "query": entry["query"],
                    }
                    for entry in entries
                ],
                per_rule_limit or 100,
            )
            completed = list(zip(entries, batch_results))
            execution_mode = "wazuh_msearch"
        except Exception:
            # Older/proxied Wazuh deployments may disable _msearch. Preserve
            # detection coverage by falling back to bounded individual calls.
            completed = []
    else:
        completed = []

    if not completed and entries:
        concurrency = max(1, int(os.environ.get("SIGMA_QUERY_CONCURRENCY", "6")))
        semaphore = asyncio.Semaphore(concurrency)

        async def bounded(entry: dict):
            async with semaphore:
                return await _execute(entry, siem_type, per_rule_limit or 100)

        completed = await asyncio.gather(
            *(bounded(entry) for entry in entries), return_exceptions=True
        )
    records: dict[str, dict] = {}
    rule_matches: list[dict] = []
    errors: list[str] = []
    for item in completed:
        if isinstance(item, Exception):
            errors.append(str(item))
            continue
        entry, result = item
        if result.get("error"):
            errors.append(f"{entry['rule_id']}: {result['error']}")
            continue
        indices: list[int] = []
        for raw in result.get("logs", []):
            key = json.dumps({field: raw.get(field) for field in EVENT_FIELDS}, sort_keys=True, default=str)
            if key not in records:
                records[key] = dict(raw)
            record = records[key]
            rules = record.setdefault("_sigma_rules", [])
            label = f"[{entry['rule_source'].lower()}] {entry['rule_id']}:{entry['title']}"
            if label not in rules:
                rules.append(label)
            record["_sigma_match"] = True
            record["_sigmahq_match"] = entry["rule_source"] == "Community"
        if result.get("logs"):
            rule_matches.append({
                "rule_id": entry["rule_id"], "title": entry["title"], "level": entry["level"],
                "source": entry["rule_source"].lower(), "matched_count": len(result["logs"]),
                "matched_indices": indices,
            })
    processed = (await process_logs_node({"logs": list(records.values())})).get("processed_logs", [])
    # Normalisation may copy records, so rebuild rule-to-reference links.
    for index, record in enumerate(processed):
        for match in rule_matches:
            label = f"[{match['source']}] {match['rule_id']}:{match['title']}"
            if label in record.get("_sigma_rules", []):
                match["matched_indices"].append(index)
    return {
        "processed_logs": processed,
        "rule_matches": rule_matches,
        "rules_evaluated": len(entries),
        "coverage": {**coverage, "execution_mode": execution_mode},
        "errors": errors,
    }


async def run_scheduled_sigma_detection(*, schedule_id: str, rule_id: str, siem_type: str,
                                        log_source_path: str | None = None) -> dict:
    started_at = time.perf_counter()
    if siem_type.lower() in LOCAL_SOURCES:
        source, rule = _selected_local_rule(rule_id)
        metadata = _metadata(source, rule)
        is_folder = siem_type.lower() != "mock"
        result = await call_tool("fetch_siem_logs", {
            # The folder parser treats "*" as a literal search term. An empty
            # query is its explicit bounded-unfiltered mode; this is the only
            # source type for which local evaluation is allowed.
            "query": "" if is_folder else "*",
            "limit": int(os.environ.get("SIGMA_FOLDER_MAX_RECORDS", "10000")) if is_folder else 1000,
            "siem_type": siem_type,
            "log_source_path": log_source_path or "",
        })
        if result.get("error"):
            raise RuntimeError(f"{siem_type} scheduled detection-rule fetch failed: {result['error']}")
        processed = (await process_logs_node({"logs": result.get("logs", [])})).get("processed_logs", [])
        evaluation = (sigma_engine.evaluate_all(processed, rules=[rule]) if source == "THOS"
                      else sigmahq_engine.evaluate_all(processed, rules=[rule]))
        indices = evaluation.get("matched_record_indices", [])
        events = [_event_view(processed[index], index) for index in indices if 0 <= index < len(processed)]
        method = "local folder detection-rule evaluation (no SIEM query engine available)"
        query = None
    else:
        entry = find_rule(rule_id, siem_type.lower())
        source, metadata = entry["rule_source"], {
            "rule_id": entry["rule_id"], "rule_title": entry["title"],
            "level": entry["level"], "tags": entry.get("tags", []),
        }
        _, result = await _execute(entry, siem_type.lower(), 200)
        processed = (await process_logs_node({"logs": result.get("logs", [])})).get("processed_logs", [])
        events = [_event_view(record, index) for index, record in enumerate(processed)]
        method = "precompiled detection-rule query executed in the SIEM"
        query = entry["query"]
    raw_events = events
    events, deduplication = deduplicate_recurring_hits(
        rule_id,
        siem_type,
        raw_events,
        schedule_id=schedule_id,
    )
    result = {
        "schedule_id": schedule_id, **metadata, "rule_source": source, "siem_type": siem_type,
        "status": "detected" if events else "no_match", "events_matched": len(events),
        "matched_events": events[:200], "compiled_query": query, "query_backend": siem_type,
        "analysis": {**_analysis(events, 1, method), "deduplication": deduplication},
    }
    result["analysis"]["triage"] = triage_detection(result)
    result["analysis"]["duration_ms"] = int(
        (time.perf_counter() - started_at) * 1000
    )
    return result


async def run_scheduled_sigma_batch(
    *, schedule_id: str, rule_ids: list[str], siem_type: str
) -> list[dict]:
    """Run a scheduled Wazuh batch, reducing batch size on transport pressure."""
    if siem_type.lower() != "wazuh":
        raise ValueError("scheduled detection-rule multi-search is currently supported for Wazuh")
    entries = [find_rule(rule_id, "wazuh") for rule_id in rule_ids]
    started_at = time.perf_counter()
    requests = [
        {"rule_id": entry["rule_id"], "query": entry["query"]}
        for entry in entries
    ]
    max_batch_size = max(
        1, int(os.environ.get("THOS_WAZUH_MSEARCH_BATCH_SIZE", "8"))
    )
    per_rule_limit = max(
        1, int(os.environ.get("THOS_WAZUH_MSEARCH_RULE_LIMIT", "10"))
    )

    def fetch_with_backpressure(items: list[dict]) -> tuple[list[dict], int]:
        """Halve an overloaded request while preserving result order."""
        try:
            return wazuh_connector.fetch_multi_logs(items, per_rule_limit), 1
        except Exception as exc:  # noqa: BLE001 - convert isolated failures to results
            if len(items) == 1:
                return [{"error": str(exc)}], 1
            midpoint = max(1, len(items) // 2)
            left, left_calls = fetch_with_backpressure(items[:midpoint])
            right, right_calls = fetch_with_backpressure(items[midpoint:])
            return left + right, 1 + left_calls + right_calls

    responses: list[dict] = []
    request_count = 0
    for start in range(0, len(requests), max_batch_size):
        chunk_responses, chunk_calls = await asyncio.to_thread(
            fetch_with_backpressure, requests[start:start + max_batch_size]
        )
        responses.extend(chunk_responses)
        request_count += chunk_calls
    shared_duration_ms = int((time.perf_counter() - started_at) * 1000)
    method = (
        "single Wazuh scheduled multi-search batch"
        if request_count == 1
        else f"adaptive Wazuh scheduled multi-search ({request_count} requests)"
    )
    results: list[dict] = []
    for entry, response in zip(entries, responses):
        source = entry["rule_source"]
        metadata = {
            "rule_id": entry["rule_id"],
            "rule_title": entry["title"],
            "level": entry["level"],
            "tags": entry.get("tags", []),
        }
        if response.get("error"):
            results.append({
                "schedule_id": schedule_id,
                **metadata,
                "rule_source": source,
                "siem_type": "wazuh",
                "status": "failed",
                "events_matched": 0,
                "matched_events": [],
                "compiled_query": entry["query"],
                "query_backend": "wazuh",
                "analysis": {
                    "method": method,
                    "duration_ms": shared_duration_ms,
                    "multi_search_requests": request_count,
                },
                "error": str(response["error"]),
            })
            continue
        processed = (
            await process_logs_node({"logs": response.get("logs", [])})
        ).get("processed_logs", [])
        raw_events = [
            _event_view(record, index) for index, record in enumerate(processed)
        ]
        events, deduplication = deduplicate_recurring_hits(
            entry["rule_id"],
            "wazuh",
            raw_events,
            schedule_id=schedule_id,
        )
        result = {
            "schedule_id": schedule_id,
            **metadata,
            "rule_source": source,
            "siem_type": "wazuh",
            "status": "detected" if events else "no_match",
            "events_matched": len(events),
            "matched_events": events[:200],
            "compiled_query": entry["query"],
            "query_backend": "wazuh",
            "analysis": {
                **_analysis(
                    events, request_count, method
                ),
                "total_hits": int(response.get("total_hits") or len(raw_events)),
                "deduplication": deduplication,
                "duration_ms": shared_duration_ms,
                "multi_search_requests": request_count,
            },
        }
        result["analysis"]["triage"] = triage_detection(result)
        results.append(result)
    return results
