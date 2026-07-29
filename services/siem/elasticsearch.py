"""Read-only Elasticsearch telemetry connector using bounded Query DSL."""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from services.observability.retry import sync_retry
from services.runtime_config import env_or_runtime


class ElasticsearchConfigError(RuntimeError):
    pass


class ElasticsearchAPIError(RuntimeError):
    pass


_INDEX_PATTERN = re.compile(r"^[A-Za-z0-9._,*-]+$")
_FORBIDDEN_KEYS = {
    "script", "script_score", "script_fields", "runtime_mappings", "percolate",
    "terms_lookup", "wrapper", "query_string",
}
_SEARCH_FIELDS = [
    "message^3", "event.original^3", "event.action^2", "event.category",
    "event.code", "host.name", "user.name", "source.ip", "destination.ip",
    "process.name", "process.command_line", "rule.name", "rule.id",
    "threat.technique.id",
]


def _setting(name: str, default: str = "") -> str:
    return str(env_or_runtime(name, "elasticsearch", default) or "")


def _positive_int(name: str, default: int) -> int:
    raw = _setting(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ElasticsearchConfigError(f"{name} must be an integer.") from exc
    if value <= 0:
        raise ElasticsearchConfigError(f"{name} must be greater than zero.")
    return value


def _get_config() -> dict[str, Any]:
    base_url = _setting("ELASTICSEARCH_URL").rstrip("/")
    index_pattern = _setting("ELASTICSEARCH_INDEX_PATTERN").strip()
    api_key = _setting("ELASTICSEARCH_API_KEY").strip()
    username = _setting("ELASTICSEARCH_USERNAME").strip()
    password = _setting("ELASTICSEARCH_PASSWORD")
    if not base_url or not index_pattern:
        raise ElasticsearchConfigError(
            "Elasticsearch requires ELASTICSEARCH_URL and ELASTICSEARCH_INDEX_PATTERN."
        )
    if not base_url.startswith(("https://", "http://")):
        raise ElasticsearchConfigError("ELASTICSEARCH_URL must start with https:// or http://.")
    if not _INDEX_PATTERN.fullmatch(index_pattern) or index_pattern in {"*", "_all"}:
        raise ElasticsearchConfigError(
            "ELASTICSEARCH_INDEX_PATTERN must be a scoped comma-separated index pattern."
        )
    if not api_key and not (username and password):
        raise ElasticsearchConfigError(
            "Configure ELASTICSEARCH_API_KEY or both ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD."
        )
    verify_ssl = _setting("ELASTICSEARCH_VERIFY_SSL", "1") != "0"
    ca_bundle = _setting("ELASTICSEARCH_CA_BUNDLE").strip()
    return {
        "base_url": base_url,
        "index_pattern": index_pattern,
        "api_key": api_key,
        "username": username,
        "password": password,
        "verify": ca_bundle if verify_ssl and ca_bundle else verify_ssl,
        "lookback_minutes": _positive_int("ELASTICSEARCH_LOOKBACK_MINUTES", 1440),
        "timeout_seconds": _positive_int("ELASTICSEARCH_REQUEST_TIMEOUT_SECONDS", 30),
        "max_results": _positive_int("ELASTICSEARCH_MAX_RESULTS", 1000),
    }


def _client_kwargs(cfg: dict[str, Any]) -> dict[str, Any]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    kwargs: dict[str, Any] = {
        "headers": headers, "timeout": cfg["timeout_seconds"], "verify": cfg["verify"],
    }
    if cfg["api_key"]:
        headers["Authorization"] = f"ApiKey {cfg['api_key']}"
    else:
        kwargs["auth"] = (cfg["username"], cfg["password"])
    return kwargs


def _validate_tree(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ElasticsearchAPIError("Elasticsearch query exceeds the maximum nesting depth.")
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in _FORBIDDEN_KEYS:
                raise ElasticsearchAPIError(f"Elasticsearch query contains forbidden construct: {key}.")
            if lowered == "range":
                raise ElasticsearchAPIError("THOS owns the Elasticsearch time range.")
            if lowered in {"simple_query_string", "multi_match"} and isinstance(child, dict):
                fields = child.get("fields", [])
                if not isinstance(fields, list) or any(str(field).split("^", 1)[0] not in {item.split("^", 1)[0] for item in _SEARCH_FIELDS} for field in fields):
                    child["fields"] = list(_SEARCH_FIELDS)
            _validate_tree(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 200:
            raise ElasticsearchAPIError("Elasticsearch query contains an oversized value list.")
        for child in value:
            _validate_tree(child, depth + 1)


def _query_clause(query: str) -> dict:
    text = (query or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        clause = parsed.get("query", parsed)
        if not isinstance(clause, dict):
            raise ElasticsearchAPIError("Elasticsearch query must contain one query object.")
        _validate_tree(clause)
        return clause
    return {
        "simple_query_string": {
            "query": text or "*",
            "fields": list(_SEARCH_FIELDS),
            "default_operator": "or",
        }
    }


def _build_body(query: str, lookback_minutes: int, limit: int) -> dict:
    clause = _query_clause(query)
    return {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m", "lte": "now"}}}],
                "must": [clause],
            }
        },
    }


def _pick(raw: dict, *paths: str, default: str = "") -> str:
    for path in paths:
        value: Any = raw
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, "", []):
            if isinstance(value, list):
                return ", ".join(str(item) for item in value)
            return str(value)
    return default


def _normalize(hit: dict) -> dict:
    raw = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    message = _pick(raw, "event.original", "message")
    return {
        "timestamp": _pick(raw, "@timestamp", "event.created", "timestamp"),
        "host": _pick(raw, "host.name", "agent.name", "observer.name"),
        "user": _pick(raw, "user.name", "user.id"),
        "event": _pick(raw, "event.action", "event.category", "event.code", default="elasticsearch_event"),
        "detail": json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str),
        "evidence_summary": message[:4000],
        "src_ip": _pick(raw, "source.ip", "client.ip"),
        "dst_ip": _pick(raw, "destination.ip", "server.ip"),
        "source_file": str(hit.get("_index", "")),
        "source_type": "elasticsearch",
        "_elasticsearch_id": str(hit.get("_id", "")),
        "_raw": raw,
    }


def _request(cfg: dict[str, Any], method: str, suffix: str, **kwargs):
    url = f"{cfg['base_url']}/{cfg['index_pattern']}/{suffix.lstrip('/')}"
    with httpx.Client(**_client_kwargs(cfg)) as client:
        def execute():
            response = client.request(method, url, **kwargs)
            if response.status_code >= 500:
                response.raise_for_status()
            return response
        response = sync_retry(execute, what=f"elasticsearch {suffix}")
    if response.status_code in (401, 403):
        raise ElasticsearchAPIError(
            f"Elasticsearch authentication/authorization failed (HTTP {response.status_code})."
        )
    if response.status_code >= 400:
        raise ElasticsearchAPIError(
            f"Elasticsearch request failed: HTTP {response.status_code} - {response.text[:500]}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise ElasticsearchAPIError("Elasticsearch returned a non-JSON response.") from exc


def discover_fields() -> list[dict[str, Any]]:
    cfg = _get_config()
    payload = _request(
        cfg, "GET", "_field_caps",
        params={"fields": "*", "ignore_unavailable": "true", "allow_no_indices": "true"},
    )
    fields = []
    for name, capabilities in sorted((payload.get("fields") or {}).items()):
        if str(name).startswith("_") or not isinstance(capabilities, dict):
            continue
        types = sorted({
            str(details.get("type") or kind)
            for kind, details in capabilities.items() if isinstance(details, dict)
        })
        fields.append({"name": str(name), "type": "|".join(types) or "unknown", "sample": None})
    return fields


def fetch_logs(
    query: str,
    limit: int = 25,
    lookback_minutes: int | None = None,
    **_ignored,
) -> dict:
    cfg = _get_config()
    bounded_limit = max(1, min(int(limit), cfg["max_results"]))
    effective_lookback = max(1, int(lookback_minutes or cfg["lookback_minutes"]))
    payload = _request(
        cfg, "POST", "_search",
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        json=_build_body(query, effective_lookback, bounded_limit),
    )
    failures = ((payload.get("_shards") or {}).get("failures") or [])
    if failures:
        raise ElasticsearchAPIError(f"Elasticsearch reported a shard failure: {failures[0]}")
    hits_container = payload.get("hits") or {}
    hits = hits_container.get("hits") or []
    if not isinstance(hits, list):
        raise ElasticsearchAPIError("Elasticsearch response did not contain a hits list.")
    records = [_normalize(hit) for hit in hits[:bounded_limit]]
    total = hits_container.get("total", 0)
    total_value = total.get("value", 0) if isinstance(total, dict) else total
    return {
        "siem_type": "elasticsearch",
        "query": query,
        "record_count": len(records),
        "total_hits": int(total_value or 0),
        "lookback_minutes": effective_lookback,
        "indices": cfg["index_pattern"],
        "logs": records,
    }
