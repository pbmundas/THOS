"""Wazuh Indexer connector for live threat-hunting telemetry.

The Wazuh manager API (normally port 55000) manages agents and the
manager. Security events are searched through the Wazuh Indexer REST
API (normally HTTPS port 9200), which exposes an OpenSearch-compatible
``_search`` endpoint.

Only read-only searches are implemented here. The target index pattern,
time range, sort order, and result cap are owned by this connector and
cannot be supplied by the query-generating model.
"""
from __future__ import annotations

import datetime
import json
import os
from typing import Any

import httpx

from services.runtime_config import env_or_runtime

from services.observability.retry import sync_retry


class WazuhConfigError(RuntimeError):
    """Raised when required Wazuh Indexer settings are missing or invalid."""


class WazuhAPIError(RuntimeError):
    """Raised when the Wazuh Indexer rejects or cannot execute a search."""


_INDEX_PATTERNS = {
    "alerts": "wazuh-alerts-*",
    "archives": "wazuh-archives-*",
    "both": "wazuh-alerts-*,wazuh-archives-*",
}

# OpenSearch features that can execute stored/dynamic code, retrieve data
# indirectly, or materially expand the cost/scope of a model-generated query.
_FORBIDDEN_QUERY_KEYS = {
    "script",
    "script_score",
    "script_fields",
    "runtime_mappings",
    "percolate",
    "terms_lookup",
    "wrapper",
    # query_string can address arbitrary fields from its query text. Use the
    # safer simple_query_string variant with a connector-owned field list.
    "query_string",
}

_SEARCH_FIELDS = [
    "full_log^3",
    "rule.description^2",
    "rule.groups",
    "rule.mitre.id",
    "rule.mitre.technique",
    # Decoder-owned fields that commonly carry the only literal artifact.
    # These are explicit mappings rather than ``data.*`` so heterogeneous
    # date/IP/numeric fields cannot turn a text token into a shard error.
    "data.command^3",
    "data.win.eventdata.commandLine^3",
    "data.user_agent^3",
    "data.url^2",
    "data.alert.signature^3",
    "agent.name",
    "agent.ip",
    "decoder.name",
    "location",
]

_SEARCH_FIELD_NAMES = {field.split("^", 1)[0] for field in _SEARCH_FIELDS}


def _positive_int_env(name: str, default: int) -> int:
    raw = env_or_runtime(name, "wazuh", str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise WazuhConfigError(f"{name} must be an integer, got {raw!r}.") from exc
    if value <= 0:
        raise WazuhConfigError(f"{name} must be greater than zero.")
    return value


def _nonnegative_int_env(name: str, default: int) -> int:
    raw = env_or_runtime(name, "wazuh", str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise WazuhConfigError(f"{name} must be an integer, got {raw!r}.") from exc
    if value < 0:
        raise WazuhConfigError(f"{name} must be zero or greater.")
    return value


def _get_config() -> dict[str, Any]:
    setting = lambda name, default="": env_or_runtime(name, "wazuh", default)
    base_url = setting("WAZUH_INDEXER_URL").rstrip("/")
    username = setting("WAZUH_INDEXER_USERNAME")
    password = setting("WAZUH_INDEXER_PASSWORD")
    source = setting("WAZUH_INDEX_SOURCE", "both").strip().lower()

    if not base_url or not username or not password:
        raise WazuhConfigError(
            "Wazuh is not configured. Set WAZUH_INDEXER_URL, "
            "WAZUH_INDEXER_USERNAME, and WAZUH_INDEXER_PASSWORD in the "
            "environment (see env.example)."
        )
    if not base_url.startswith(("https://", "http://")):
        raise WazuhConfigError(
            "WAZUH_INDEXER_URL must start with https:// (or http:// for an "
            "explicitly unsecured development endpoint)."
        )
    if source not in _INDEX_PATTERNS:
        raise WazuhConfigError(
            "WAZUH_INDEX_SOURCE must be one of: alerts, archives, both."
        )

    verify_ssl = setting("WAZUH_VERIFY_SSL", "1") != "0"
    ca_bundle = setting("WAZUH_CA_BUNDLE").strip()
    verify: bool | str = ca_bundle if verify_ssl and ca_bundle else verify_ssl

    return {
        "base_url": base_url,
        "username": username,
        "password": password,
        "source": source,
        "index_pattern": _INDEX_PATTERNS[source],
        "verify": verify,
        "lookback_minutes": _positive_int_env("WAZUH_LOOKBACK_MINUTES", 1440),
        "timeout_seconds": _positive_int_env("WAZUH_REQUEST_TIMEOUT_SECONDS", 30),
        "max_results": _positive_int_env("WAZUH_MAX_RESULTS", 1000),
    }


def _strip_markdown_fence(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _validate_query_tree(value: Any, depth: int = 0, trusted_sigma: bool = False) -> None:
    if depth > 12:
        raise WazuhAPIError("Wazuh query exceeds the maximum nesting depth.")
    if isinstance(value, dict):
        for key, child in value.items():
            lowered_key = str(key).lower()
            if lowered_key in _FORBIDDEN_QUERY_KEYS and not (
                trusted_sigma and lowered_key == "query_string"
            ):
                raise WazuhAPIError(
                    f"Wazuh query contains forbidden construct: {key}."
                )
            # THOS owns the only time range in the request. Model-generated
            # ranges are both unnecessary and prone to putting natural-language
            # tokens into date/numeric fields, which makes OpenSearch fail a
            # shard before returning any evidence.
            if lowered_key == "range":
                raise WazuhAPIError(
                    "Wazuh query contains a model-supplied range; THOS owns "
                    "the hunt time range."
                )
            if lowered_key == "terms" and isinstance(child, dict):
                for terms_value in child.values():
                    if isinstance(terms_value, dict) and {
                        "index", "id", "path"
                    }.issubset({str(item).lower() for item in terms_value}):
                        raise WazuhAPIError(
                            "Wazuh query contains forbidden terms lookup."
                        )
            _validate_query_tree(child, depth + 1, trusted_sigma)
    elif isinstance(value, list):
        if len(value) > 200:
            raise WazuhAPIError("Wazuh query contains an oversized value list.")
        for child in value:
            _validate_query_tree(child, depth + 1, trusted_sigma)


def _sanitize_query_fields(value: Any) -> None:
    """Keep free-text searches away from heterogeneous mapped fields.

    In Wazuh, ``data.*`` expands to strings, IP addresses, numbers, and dates.
    A text token such as ``adversary`` then gets parsed as a date on some
    shards and aborts the whole search. Restrict free-text clauses to the
    connector's known text/keyword fields, regardless of model output.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"simple_query_string", "multi_match"} \
                    and isinstance(child, dict):
                supplied = child.get("fields")
                if isinstance(supplied, list):
                    safe_fields = [
                        field for field in supplied
                        if isinstance(field, str)
                        and field.split("^", 1)[0] in _SEARCH_FIELD_NAMES
                    ]
                    child["fields"] = safe_fields or list(_SEARCH_FIELDS)
                else:
                    child["fields"] = list(_SEARCH_FIELDS)
            _sanitize_query_fields(child)
    elif isinstance(value, list):
        for child in value:
            _sanitize_query_fields(child)


def _parse_query_clause(query: str, trusted_sigma: bool = False) -> dict:
    """Accept JSON Query DSL or safely degrade plain text to a bounded search."""
    text = _strip_markdown_fence(query)
    if not text or text == "*":
        return {"match_all": {}}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # simple_query_string discards invalid operators instead of failing the
        # whole request, making it a safe fallback for natural-language model
        # output and targeted follow-up terms.
        return {
            "simple_query_string": {
                "query": text[:1000],
                "fields": _SEARCH_FIELDS,
                "default_operator": "and",
            }
        }

    if not isinstance(payload, dict):
        raise WazuhAPIError("Wazuh Query DSL must be a JSON object.")

    # The model is allowed to return either {"query": {...}} or the query
    # clause itself. Ignore model-supplied size/sort/index fields by extracting
    # only the query member.
    clause = payload.get("query", payload)
    if not isinstance(clause, dict):
        raise WazuhAPIError("Wazuh Query DSL 'query' must be a JSON object.")
    _validate_query_tree(clause, trusted_sigma=trusted_sigma)
    _sanitize_query_fields(clause)
    return clause


def _build_search_body(query: str, lookback_minutes: int, limit: int,
                       trusted_sigma: bool = False) -> dict:
    clause = _parse_query_clause(query, trusted_sigma=trusted_sigma)
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        minutes=lookback_minutes
    )
    return {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": start.isoformat(), "lte": "now"}}}
                ],
                "must": [clause],
            }
        },
    }


def _get_path(raw: dict, path: str) -> Any:
    value: Any = raw
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _pick(raw: dict, *paths: str, default: str = "") -> str:
    for path in paths:
        value = _get_path(raw, path)
        if value not in (None, "", []):
            if isinstance(value, list):
                return ", ".join(str(item) for item in value)
            return str(value)
    return default


def _normalize_record(hit: dict) -> dict:
    """Map a Wazuh Indexer hit onto THOS's normalized evidence schema."""
    raw = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    index = str(hit.get("_index", ""))
    detail = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str)
    evidence_parts = []
    evidence_fields = (
        ("rule", "rule.description"),
        ("network alert", "data.alert.signature"),
        ("MITRE ID", "rule.mitre.id"),
        ("MITRE technique", "rule.mitre.technique"),
        ("full log", "full_log"),
        ("URL", "data.url"),
        ("user agent", "data.user_agent"),
        ("command", "data.command"),
        ("command line", "data.win.eventdata.commandLine"),
        ("process", "data.win.eventdata.image"),
        ("parent process", "data.win.eventdata.parentImage"),
        ("source IP", "data.src_ip"),
        ("source IP", "data.srcip"),
        ("destination IP", "data.dest_ip"),
        ("destination IP", "data.dstip"),
        ("source port", "data.src_port"),
        ("source port", "data.srcport"),
        ("destination port", "data.dest_port"),
        ("destination port", "data.dstport"),
        ("flow destination port", "data.flow.dest_port"),
        ("protocol", "data.proto"),
        ("TCP SYN", "data.tcp.syn"),
        ("flow state", "data.flow.state"),
    )
    for label, field_path in evidence_fields:
        value = _pick(raw, field_path)
        if value:
            evidence_parts.append(f"{label}: {value[:1200]}")
    evidence_summary = " | ".join(evidence_parts)[:4000]

    return {
        "timestamp": _pick(raw, "@timestamp", "timestamp"),
        "host": _pick(raw, "agent.name", "predecoder.hostname", "data.hostname"),
        "user": _pick(
            raw,
            "data.dstuser",
            "data.srcuser",
            "data.user",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.subjectUserName",
        ),
        "event": _pick(
            raw,
            "rule.description",
            "data.win.system.eventID",
            "event.code",
            "decoder.name",
            default="wazuh_event",
        ),
        "detail": detail,
        # Keep the fields that carry an artifact's identity ahead of the
        # bounded raw JSON. This prevents a long Wazuh document from hiding
        # high-signal values (for example the Nmap NSE user-agent) beyond the
        # reasoning prompt's raw-detail limit.
        "evidence_summary": evidence_summary,
        # Wazuh decoder field names vary by integration. Suricata's native
        # EVE mapping uses src_ip/dest_ip while other decoders use srcip/dstip.
        # Agent IP is only a final source fallback because it identifies the
        # collector host, not necessarily the network initiator.
        "src_ip": _pick(
            raw, "data.src_ip", "data.flow.src_ip", "data.srcip", "srcip",
            "agent.ip",
        ),
        "dst_ip": _pick(
            raw, "data.dest_ip", "data.flow.dest_ip", "data.dstip", "dstip",
        ),
        "src_port": _pick(
            raw, "data.src_port", "data.flow.src_port", "data.srcport", "srcport",
        ),
        "dst_port": _pick(
            raw, "data.dest_port", "data.flow.dest_port", "data.dstport", "dstport",
        ),
        "protocol": _pick(raw, "data.proto", "data.protocol", "protocol"),
        "source_file": index,
        "source_type": "wazuh",
        "_wazuh_id": str(hit.get("_id", "")),
        "_raw": raw,
    }


def _dedupe_key(record: dict) -> tuple:
    raw = record.get("_raw", {})
    raw_identity = _pick(raw, "full_log", "message")
    if not raw_identity:
        return (record.get("source_file", ""), record.get("_wazuh_id", ""))
    return (
        record.get("timestamp", ""),
        _pick(raw, "agent.id", "agent.name"),
        _pick(raw, "location"),
        raw_identity,
    )


def _deduplicate(records: list[dict]) -> list[dict]:
    """Remove alert/archive copies of the same event, preferring the alert."""
    chosen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for record in records:
        key = _dedupe_key(record)
        if key not in chosen:
            chosen[key] = record
            order.append(key)
            continue
        current = chosen[key]
        if "wazuh-alerts-" in record.get("source_file", "") and \
                "wazuh-alerts-" not in current.get("source_file", ""):
            chosen[key] = record
    return [chosen[key] for key in order]


def discover_fields() -> list[dict[str, Any]]:
    """Read the Indexer's field capabilities without retrieving event values.

    A recent-event sample can contain only one log family and therefore hide
    valid fields used by other agents or decoders. Field capabilities provide
    the complete searchable schema needed for safe detection-rule compilation.
    """
    cfg = _get_config()
    url = f"{cfg['base_url']}/{cfg['index_pattern']}/_field_caps"
    with httpx.Client(
        auth=(cfg["username"], cfg["password"]),
        headers={"Accept": "application/json"},
        timeout=cfg["timeout_seconds"],
        verify=cfg["verify"],
    ) as client:
        def _get_field_caps():
            result = client.get(
                url,
                params={
                    "fields": "*",
                    "ignore_unavailable": "true",
                    "allow_no_indices": "true",
                },
            )
            if result.status_code >= 500:
                result.raise_for_status()
            return result

        response = sync_retry(_get_field_caps, what="wazuh indexer field capabilities")

    if response.status_code in (401, 403):
        raise WazuhAPIError(
            f"Wazuh Indexer field discovery is not authorized (HTTP {response.status_code})."
        )
    if response.status_code >= 400:
        raise WazuhAPIError(
            f"Wazuh Indexer field discovery failed: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )
    try:
        raw_fields = response.json().get("fields", {})
    except ValueError as exc:
        raise WazuhAPIError("Wazuh Indexer returned non-JSON field capabilities.") from exc
    if not isinstance(raw_fields, dict):
        raise WazuhAPIError("Wazuh Indexer field capabilities are malformed.")

    fields: list[dict[str, Any]] = []
    for name, capabilities in sorted(raw_fields.items(), key=lambda pair: pair[0].casefold()):
        if str(name).startswith("_") or not isinstance(capabilities, dict):
            continue
        types = sorted({
            str(details.get("type") or field_type)
            for field_type, details in capabilities.items()
            if isinstance(details, dict)
        })
        fields.append({"name": str(name), "type": "|".join(types) or "unknown", "sample": None})
    return fields


def resource_pressure() -> dict[str, Any]:
    """Return a small, read-only Indexer pressure snapshot.

    Scheduled detection batches use this before increasing request width. The
    probe deliberately has no retry loop: if a stressed or restarting Indexer
    cannot answer promptly, callers must fail closed instead of adding more
    work to it.
    """
    cfg = _get_config()
    url = f"{cfg['base_url']}/_nodes/stats/jvm,thread_pool"
    try:
        with httpx.Client(
            auth=(cfg["username"], cfg["password"]),
            headers={"Accept": "application/json"},
            timeout=min(float(cfg["timeout_seconds"]), 5.0),
            verify=cfg["verify"],
        ) as client:
            response = client.get(
                url,
                params={
                    "filter_path": (
                        "nodes.*.jvm.mem.heap_used_percent,"
                        "nodes.*.jvm.mem.heap_used_in_bytes,"
                        "nodes.*.jvm.mem.heap_max_in_bytes,"
                        "nodes.*.thread_pool.search.queue,"
                        "nodes.*.thread_pool.search.rejected"
                    )
                },
            )
        if response.status_code >= 400:
            return {
                "available": False,
                "error": f"Indexer pressure probe returned HTTP {response.status_code}",
            }
        payload = response.json()
        nodes = payload.get("nodes") if isinstance(payload, dict) else {}
        if not isinstance(nodes, dict) or not nodes:
            return {"available": False, "error": "Indexer pressure probe returned no nodes"}
        heap_values: list[int] = []
        heap_used_bytes = 0
        heap_max_bytes = 0
        search_queue = 0
        search_rejected = 0
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            memory = ((node.get("jvm") or {}).get("mem") or {})
            thread_pool = ((node.get("thread_pool") or {}).get("search") or {})
            if memory.get("heap_used_percent") is not None:
                heap_values.append(int(memory["heap_used_percent"]))
            heap_used_bytes += int(memory.get("heap_used_in_bytes") or 0)
            heap_max_bytes += int(memory.get("heap_max_in_bytes") or 0)
            search_queue += int(thread_pool.get("queue") or 0)
            search_rejected += int(thread_pool.get("rejected") or 0)
        return {
            "available": bool(heap_values),
            "heap_used_percent": max(heap_values) if heap_values else None,
            "heap_used_bytes": heap_used_bytes,
            "heap_max_bytes": heap_max_bytes,
            "search_queue": search_queue,
            "search_rejected": search_rejected,
            "node_count": len(nodes),
        }
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {
            "available": False,
            "error": f"Indexer pressure probe failed: {type(exc).__name__}: {exc}",
        }


def fetch_logs(
    query: str,
    limit: int = 25,
    trusted_sigma: bool = False,
    lookback_minutes: int | None = None,
    **_ignored,
) -> dict:
    """Execute a bounded read-only search against the Wazuh Indexer."""
    cfg = _get_config()
    bounded_limit = max(1, min(int(limit), cfg["max_results"]))
    effective_lookback = max(1, int(lookback_minutes or cfg["lookback_minutes"]))
    body = _build_search_body(query, effective_lookback, bounded_limit, trusted_sigma)
    url = f"{cfg['base_url']}/{cfg['index_pattern']}/_search"

    with httpx.Client(
        auth=(cfg["username"], cfg["password"]),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=cfg["timeout_seconds"],
        verify=cfg["verify"],
    ) as client:
        def _post_search():
            result = client.post(
                url,
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                json=body,
            )
            # Feed transient server failures into the shared retry helper;
            # authentication/query 4xx responses remain immediate failures.
            if result.status_code >= 500:
                result.raise_for_status()
            return result

        response = sync_retry(
            _post_search,
            what="wazuh indexer search",
        )

    if response.status_code in (401, 403):
        raise WazuhAPIError(
            f"Wazuh Indexer authentication/authorization failed (HTTP {response.status_code})."
        )
    if response.status_code >= 400:
        raise WazuhAPIError(
            f"Wazuh Indexer search failed: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise WazuhAPIError("Wazuh Indexer returned a non-JSON response.") from exc

    shard_failures = ((payload.get("_shards") or {}).get("failures") or [])
    if shard_failures:
        reason = shard_failures[0].get("reason", shard_failures[0])
        raise WazuhAPIError(f"Wazuh Indexer reported a shard failure: {reason}")

    hits = ((payload.get("hits") or {}).get("hits") or [])
    if not isinstance(hits, list):
        raise WazuhAPIError("Wazuh Indexer response did not contain a hits list.")

    records = _deduplicate([_normalize_record(hit) for hit in hits])[:bounded_limit]
    total = (payload.get("hits") or {}).get("total", 0)
    total_value = total.get("value", 0) if isinstance(total, dict) else total
    return {
        "siem_type": "wazuh",
        "query": query,
        "record_count": len(records),
        "total_hits": int(total_value or 0),
        "lookback_minutes": effective_lookback,
        "indices": cfg["index_pattern"],
        "logs": records,
    }


def fetch_multi_logs(requests: list[dict], limit: int = 100) -> list[dict]:
    """Execute trusted Sigma queries in one OpenSearch ``_msearch`` request."""
    if not requests:
        return []
    cfg = _get_config()
    bounded_limit = max(1, min(int(limit), cfg["max_results"]))
    lines: list[str] = []
    for request in requests:
        query = str(request.get("query") or "")
        # An index is connector-owned and never accepted from the compiled rule.
        lines.append(json.dumps({
            "index": cfg["index_pattern"],
            "ignore_unavailable": True,
            "allow_no_indices": True,
        }, separators=(",", ":")))
        search_body = _build_search_body(
            query, cfg["lookback_minutes"], bounded_limit, trusted_sigma=True
        )
        # Scheduled rules only need to know whether evidence exists and retain
        # a bounded sample. Exact counts across a large enterprise index are
        # not worth the heap cost of ``track_total_hits: true``.
        search_body["track_total_hits"] = max(
            bounded_limit,
            _positive_int_env("WAZUH_MSEARCH_TRACK_TOTAL_HITS", 1000),
        )
        lines.append(json.dumps(search_body, separators=(",", ":")))
    body = "\n".join(lines) + "\n"
    url = f"{cfg['base_url']}/_msearch"

    with httpx.Client(
        auth=(cfg["username"], cfg["password"]),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-ndjson",
        },
        timeout=cfg["timeout_seconds"],
        verify=cfg["verify"],
    ) as client:
        def _post_multi_search():
            result = client.post(url, content=body)
            if result.status_code >= 500:
                result.raise_for_status()
            return result

        response = sync_retry(
            _post_multi_search,
            what="wazuh indexer multi-search",
            # The batch scheduler owns resource-aware splitting. Replaying a
            # memory-heavy request several times while the Indexer restarts can
            # turn one rejected search into a crash loop.
            retries=_nonnegative_int_env("WAZUH_MSEARCH_RETRIES", 0),
        )

    if response.status_code in (401, 403):
        raise WazuhAPIError(
            "Wazuh Indexer multi-search is not authorized "
            f"(HTTP {response.status_code})."
        )
    if response.status_code >= 400:
        raise WazuhAPIError(
            f"Wazuh Indexer multi-search failed: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )
    try:
        responses = response.json().get("responses") or []
    except ValueError as exc:
        raise WazuhAPIError(
            "Wazuh Indexer returned a non-JSON multi-search response."
        ) from exc
    if not isinstance(responses, list) or len(responses) != len(requests):
        raise WazuhAPIError(
            "Wazuh Indexer multi-search response count did not match the request."
        )

    results: list[dict] = []
    for request, payload in zip(requests, responses):
        error = payload.get("error") if isinstance(payload, dict) else "malformed response"
        if error:
            results.append({
                "siem_type": "wazuh",
                "query": request.get("query", ""),
                "rule_id": request.get("rule_id", ""),
                "record_count": 0,
                "total_hits": 0,
                "logs": [],
                "error": json.dumps(error, default=str)[:1000],
            })
            continue
        shard_failures = ((payload.get("_shards") or {}).get("failures") or [])
        if shard_failures:
            results.append({
                "siem_type": "wazuh",
                "query": request.get("query", ""),
                "rule_id": request.get("rule_id", ""),
                "record_count": 0,
                "total_hits": 0,
                "logs": [],
                "error": f"shard failure: {str(shard_failures[0])[:900]}",
            })
            continue
        hits_payload = payload.get("hits") or {}
        hits = hits_payload.get("hits") or []
        if not isinstance(hits, list):
            hits = []
        records = _deduplicate(
            [_normalize_record(hit) for hit in hits]
        )[:bounded_limit]
        total = hits_payload.get("total", 0)
        total_value = total.get("value", 0) if isinstance(total, dict) else total
        results.append({
            "siem_type": "wazuh",
            "query": request.get("query", ""),
            "rule_id": request.get("rule_id", ""),
            "record_count": len(records),
            "total_hits": int(total_value or 0),
            "indices": cfg["index_pattern"],
            "logs": records,
        })
    return results
