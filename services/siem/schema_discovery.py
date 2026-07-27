"""Bounded SIEM schema discovery with stale-safe caching and drift reporting.

The discovery pass intentionally samples a small number of recent events. Raw
vendor payloads are already retained under ``_raw`` by every live connector, so
the inventory reflects fields the SIEM actually returned rather than THOS's
normalized evidence envelope.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from services.observability import cache
from services.runtime_config import get_value
from services.siem import siem_connector


SCHEMA_NAMESPACE = "siem_schema"
DRIFT_NAMESPACE = "siem_schema_drift"
DEFAULT_REFRESH_SECONDS = 7 * 24 * 60 * 60
DEFAULT_RETENTION_SECONDS = 35 * 24 * 60 * 60
MAX_FIELDS = 10_000
MAX_SAMPLE_LENGTH = 160
_SENSITIVE_MARKERS = ("password", "passwd", "secret", "token", "credential", "api_key", "apikey")

_SAMPLE_QUERIES = {
    "mock": "*",
    "folder": "",
    "local_folder": "",
    "file": "",
    "local": "",
    "wazuh": '{"query":{"match_all":{}}}',
    "splunk": "search * | head 50",
    "qradar": "SELECT * FROM events LAST 5 MINUTES",
    "logrhythm": "*",
    "elasticsearch": '{"query":{"match_all":{}}}',
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        child_types = sorted({_infer_type(item) for item in value[:10]})
        return f"list[{','.join(child_types) or 'unknown'}]"
    text = str(value).strip()
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _parse_timestamp(text) is not None and ("T" in text or ":" in text):
        return "timestamp"
    return "string"


def _sample_value(path: str, value: Any) -> Any:
    lowered = path.casefold()
    if any(marker in lowered for marker in _SENSITIVE_MARKERS):
        return "[redacted]"
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    else:
        rendered = str(value)
    return rendered if len(rendered) <= MAX_SAMPLE_LENGTH else rendered[:MAX_SAMPLE_LENGTH] + "..."


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    fields: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, dict):
                fields.extend(_flatten(child, path))
            else:
                fields.append((path, child))
    elif prefix:
        fields.append((prefix, value))
    return fields


def inventory_from_logs(logs: list[dict]) -> list[dict]:
    """Return stable field metadata from raw vendor records."""
    observed: dict[str, dict[str, Any]] = {}
    for record in logs:
        raw = record.get("_raw") if isinstance(record.get("_raw"), dict) else record
        for path, value in _flatten(raw):
            if path.startswith("_") or len(observed) >= MAX_FIELDS and path not in observed:
                continue
            item = observed.setdefault(path, {"name": path, "types": set(), "sample": None})
            item["types"].add(_infer_type(value))
            if item["sample"] is None and value not in (None, "", [], {}):
                item["sample"] = _sample_value(path, value)
    return [
        {
            "name": name,
            "type": "|".join(sorted(item["types"])) or "unknown",
            "sample": item["sample"],
        }
        for name, item in sorted(observed.items(), key=lambda pair: pair[0].casefold())
    ]


def _merge_field_inventories(*inventories: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for inventory in inventories:
        for item in inventory:
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            existing = merged.get(name)
            if existing is None:
                merged[name] = dict(item)
            elif existing.get("sample") in (None, "") and item.get("sample") not in (None, ""):
                merged[name] = {**existing, **item}
    return [merged[name] for name in sorted(merged, key=str.casefold)]


def schema_hash(fields: list[dict]) -> str:
    canonical = [{"name": item.get("name"), "type": item.get("type")} for item in fields]
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def diff_schemas(previous: dict | None, current: dict) -> dict:
    before = {
        str(item.get("name")): str(item.get("type", "unknown"))
        for item in (previous or {}).get("fields", [])
        if item.get("name")
    }
    after = {
        str(item.get("name")): str(item.get("type", "unknown"))
        for item in current.get("fields", [])
        if item.get("name")
    }
    return {
        "siem_type": current.get("siem_type"),
        "previous_schema_version": (previous or {}).get("schema_version"),
        "schema_version": current.get("schema_version"),
        "added": sorted(set(after) - set(before), key=str.casefold),
        "removed": sorted(set(before) - set(after), key=str.casefold),
        "changed_type": [
            {"field": name, "before": before[name], "after": after[name]}
            for name in sorted(set(before) & set(after), key=str.casefold)
            if before[name] != after[name]
        ],
        "changed": before != after,
        "detected_at": current.get("last_verified"),
    }


def get_cached_siem_schema(siem_type: str) -> dict:
    key = (siem_type or "").lower()
    snapshot = cache.cache_get(SCHEMA_NAMESPACE, key)
    if not isinstance(snapshot, dict):
        inventory = get_value("siem_field_inventory", key, default={})
        if isinstance(inventory, dict) and inventory.get("fields"):
            metadata = inventory.get("field_metadata")
            fields = (
                metadata
                if isinstance(metadata, list) and metadata
                else [
                    {"name": str(name), "type": "unknown", "sample": None}
                    for name in inventory.get("fields", [])
                    if str(name).strip()
                ]
            )
            snapshot = {
                "siem_type": key,
                "fields": fields,
                "field_count": len(fields),
                "records_sampled": int(inventory.get("records_sampled", 0)),
                "last_verified": inventory.get("last_verified")
                or inventory.get("uploaded_at")
                or "",
                "schema_version": inventory.get("schema_version") or schema_hash(fields),
                "source": inventory.get("source") or "runtime_inventory",
            }
        else:
            return {"siem_type": key, "fields": [], "hit": False, "stale": True}
    verified = _parse_timestamp(snapshot.get("last_verified"))
    refresh_seconds = max(
        300, int(os.environ.get("SIEM_SCHEMA_REFRESH_SECONDS", str(DEFAULT_REFRESH_SECONDS)))
    )
    stale = verified is None or _utc_now() - verified > timedelta(seconds=refresh_seconds)
    return {**snapshot, "hit": True, "stale": stale}


def alert_on_schema_drift(siem_type: str) -> dict:
    key = (siem_type or "").lower()
    drift = cache.cache_get(DRIFT_NAMESPACE, key)
    if isinstance(drift, dict):
        return drift
    return {
        "siem_type": key,
        "added": [],
        "removed": [],
        "changed_type": [],
        "changed": False,
        "available": False,
    }


def discover_siem_fields(
    siem_type: str,
    sample_limit: int = 50,
    log_source_path: str = "",
) -> dict:
    """Sample recent telemetry, cache its raw field inventory, and report drift."""
    key = (siem_type or "").lower()
    if key not in _SAMPLE_QUERIES:
        raise ValueError(f"unsupported SIEM type for schema discovery: {siem_type}")
    bounded_limit = max(1, min(int(sample_limit), 200))
    result = siem_connector.fetch_logs(
        _SAMPLE_QUERIES[key],
        bounded_limit,
        siem_type=key,
        log_source_path=log_source_path,
        bypass_cache=True,
    )
    if result.get("error"):
        raise RuntimeError(str(result["error"]))
    fields = inventory_from_logs(list(result.get("logs") or []))
    discovery_method = "recent_event_sample"
    discovery_warning = ""
    if key in {"wazuh", "elasticsearch"}:
        # The sample can be homogeneous (for example, only ossec health
        # records), which previously made every process/network rule appear
        # unsupported. Merge the read-only Indexer schema so compilation sees
        # all searchable fields while samples remain bounded.
        from services.siem import elasticsearch, wazuh
        try:
            connector = wazuh if key == "wazuh" else elasticsearch
            fields = _merge_field_inventories(connector.discover_fields(), fields)
            discovery_method = "index_field_capabilities_and_recent_event_sample"
        except Exception as exc:  # noqa: BLE001 - retain the verified bounded sample
            discovery_warning = f"Indexer field capabilities unavailable: {exc}"
    now = _utc_now().isoformat()
    snapshot = {
        "siem_type": key,
        "fields": fields,
        "field_count": len(fields),
        "records_sampled": len(result.get("logs") or []),
        "last_verified": now,
        "schema_version": schema_hash(fields),
        "sample_query": _SAMPLE_QUERIES[key],
        "discovery_method": discovery_method,
        "discovery_warning": discovery_warning,
    }
    previous = get_cached_siem_schema(key)
    drift = diff_schemas(previous if previous.get("hit") else None, snapshot)
    retention = max(
        DEFAULT_REFRESH_SECONDS,
        int(os.environ.get("SIEM_SCHEMA_RETENTION_SECONDS", str(DEFAULT_RETENTION_SECONDS))),
    )
    cache.cache_set(SCHEMA_NAMESPACE, key, snapshot, ttl=retention)
    cache.cache_set(DRIFT_NAMESPACE, key, drift, ttl=retention)
    return {**snapshot, "stale": False, "drift": drift}
