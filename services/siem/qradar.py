"""
QRadar SIEM connector — Phase 2 real implementation.

Talks to the QRadar **Ariel Search REST API** (the API used to run AQL
searches against events/flows), using the documented async pattern:

    1. POST {base_url}/api/ariel/searches
                                    -> submit an AQL query, get a
                                       search_id back
    2. GET  {base_url}/api/ariel/searches/{search_id}
                                    -> poll until status is COMPLETED
                                       (or CANCELED/ERROR)
    3. GET  {base_url}/api/ariel/searches/{search_id}/results
                                    -> retrieve results (JSON)

Reference: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-arielsearches

Configuration (see env.example):
    QRADAR_BASE_URL       e.g. https://qradar.example.com
    QRADAR_TOKEN          QRadar API token (Admin -> Authorized
                           Services). Sent as `SEC: <token>` header, per
                           QRadar's API auth scheme (not Bearer).
    QRADAR_VERIFY_SSL     "0" to disable TLS verification (self-signed
                           console certs are common in on-prem labs).
                           Defaults to "1".
    QRADAR_API_VERSION    API version header value, default "20.0".
    QRADAR_LOOKBACK_MINUTES   Search window size when the query doesn't
                           already include a START/STOP clause, default
                           1440 (24h).
    QRADAR_POLL_INTERVAL_SECONDS  Delay between search-status polls,
                           default 2.
    QRADAR_POLL_TIMEOUT_SECONDS   Give up waiting for completion after
                           this many seconds, default 60.

The query string handed in here is expected to already be a valid AQL
statement (query_generator.py prompts the LLM to produce AQL directly
for siem_type="qradar", grounded in the field mapping from
siem_kb.py) — this module does not build or rewrite AQL, it just runs
it, adding a default time window only if the AQL has none.

Known caveats / things to verify against your specific QRadar version
before relying on this in production:
  - Only appends `START ... STOP ...` when the AQL doesn't already
    contain a `START`/`LAST` time clause — QRadar rejects AQL with
    conflicting time clauses, so this is deliberately conservative
    rather than trying to merge/replace an existing one.
  - `_normalize_record` tries several common QRadar/AQL column-name
    aliases per field rather than assuming one fixed schema, since AQL
    `SELECT` output columns depend on exactly what the generated query
    selected.
"""
from __future__ import annotations

import os
import time
import re
import datetime
import logging
from typing import Any

import httpx

from services.observability.retry import sync_retry

logger = logging.getLogger(__name__)


class QRadarConfigError(RuntimeError):
    """Raised when required QRadar connection settings are missing."""


class QRadarAPIError(RuntimeError):
    """Raised when the QRadar Ariel API returns an error or unexpected shape."""


def _get_config() -> dict:
    base_url = os.environ.get("QRADAR_BASE_URL", "").rstrip("/")
    token = os.environ.get("QRADAR_TOKEN", "")
    if not base_url or not token:
        raise QRadarConfigError(
            "QRadar is not configured. Set QRADAR_BASE_URL "
            "(e.g. https://<qradar-console>) and QRADAR_TOKEN in the "
            "environment (see env.example)."
        )
    return {
        "base_url": base_url,
        "token": token,
        "verify_ssl": os.environ.get("QRADAR_VERIFY_SSL", "1") != "0",
        "api_version": os.environ.get("QRADAR_API_VERSION", "20.0"),
        "lookback_minutes": int(os.environ.get("QRADAR_LOOKBACK_MINUTES", "1440")),
        "poll_interval": float(os.environ.get("QRADAR_POLL_INTERVAL_SECONDS", "2")),
        "poll_timeout": float(os.environ.get("QRADAR_POLL_TIMEOUT_SECONDS", "60")),
    }


def _headers(token: str, api_version: str) -> dict:
    return {
        "SEC": token,
        "Version": api_version,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }


_TIME_CLAUSE_RE = re.compile(r"\b(START|LAST)\b", re.IGNORECASE)


def _add_time_window(aql: str, lookback_minutes: int, limit: int) -> str:
    aql = (aql or "").strip().rstrip(";")
    if not aql:
        aql = "SELECT * FROM events"

    if not aql.upper().startswith("SELECT"):
        # A bare AQL WHERE-clause fragment or keyword list, same
        # tolerance file_log_parser-style callers might produce.
        aql = f"SELECT * FROM events WHERE {aql}"

    if " LIMIT " not in aql.upper():
        aql = f"{aql} LIMIT {limit}"

    if _TIME_CLAUSE_RE.search(aql):
        return aql

    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=lookback_minutes)
    fmt = "%Y-%m-%d %H:%M:%S"
    return f"{aql} START '{start.strftime(fmt)}' STOP '{now.strftime(fmt)}'"


def _submit_search(client: httpx.Client, cfg: dict, query: str, limit: int) -> str:
    aql = _add_time_window(query, cfg["lookback_minutes"], limit)
    resp = sync_retry(
        client.post, f"{cfg['base_url']}/api/ariel/searches",
        data={"query_expression": aql},
        what="qradar submit ariel search",
    )
    if resp.status_code >= 400:
        raise QRadarAPIError(
            f"ariel search submit failed: HTTP {resp.status_code} — {resp.text[:500]}"
        )
    payload = resp.json()
    search_id = payload.get("search_id") or payload.get("cursor_id")
    if not search_id:
        raise QRadarAPIError(f"ariel search submit returned no search_id: {payload}")
    return search_id


def _poll_search_status(client: httpx.Client, cfg: dict, search_id: str) -> None:
    deadline = time.monotonic() + cfg["poll_timeout"]
    url = f"{cfg['base_url']}/api/ariel/searches/{search_id}"

    while True:
        resp = sync_retry(
            client.get, url, what="qradar poll search status",
        )
        if resp.status_code >= 400:
            raise QRadarAPIError(
                f"search status check failed: HTTP {resp.status_code} — {resp.text[:500]}"
            )
        payload = resp.json()
        status = payload.get("status", "")

        if status == "COMPLETED":
            return
        if status in ("CANCELED", "ERROR"):
            raise QRadarAPIError(
                f"ariel search {search_id} ended with status {status}: {payload}"
            )

        if time.monotonic() >= deadline:
            logger.warning(
                "QRadar ariel search %s did not complete within %ss "
                "(last status=%s); attempting to read partial results.",
                search_id, cfg["poll_timeout"], status,
            )
            return

        time.sleep(cfg["poll_interval"])


def _fetch_results(client: httpx.Client, cfg: dict, search_id: str, limit: int) -> list[dict]:
    resp = sync_retry(
        client.get, f"{cfg['base_url']}/api/ariel/searches/{search_id}/results",
        headers={"Range": f"items=0-{max(limit - 1, 0)}"},
        what="qradar fetch ariel results",
    )
    if resp.status_code >= 400:
        raise QRadarAPIError(
            f"results fetch failed: HTTP {resp.status_code} — {resp.text[:500]}"
        )
    payload = resp.json()
    # Ariel results come back keyed by the AQL's FROM target
    # ("events", "flows", ...) rather than a single fixed key.
    for key in ("events", "flows", "results"):
        val = payload.get(key)
        if isinstance(val, list):
            return val
    return []


def _pick(raw: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        val = raw.get(key)
        if val not in (None, ""):
            return str(val)
    return default


def _normalize_record(raw: dict) -> dict:
    """Map a raw QRadar/AQL result dict onto THOS's common log schema
    (timestamp/host/user/event/detail/src_ip) — the same shape produced
    by mock mode, file_log_parser, and the LogRhythm/Splunk connectors,
    so downstream nodes don't need to know which SIEM the data came
    from."""
    return {
        "timestamp": _pick(raw, "starttime", "devicetime", "Start Time"),
        "host": _pick(raw, "sourceip", "logsourcename", "Log Source"),
        "user": _pick(raw, "username", "Username", "identityusername"),
        "event": _pick(raw, "qidname", "categoryname", "eventname", default="event"),
        "detail": _pick(raw, "payload", "message", "Message"),
        "src_ip": _pick(raw, "sourceip", "Source IP"),
        "_raw": raw,
    }


def fetch_logs(query: str, limit: int = 25, **_ignored) -> dict:
    """
    Entry point dispatched from siem_connector.fetch_logs when
    siem_type == "qradar". Synchronous (uses httpx.Client) so it can be
    called directly from the sync `fetch_siem_logs` MCP tool without any
    event-loop juggling — same shape as logrhythm.fetch_logs and
    splunk.fetch_logs.
    """
    cfg = _get_config()

    with httpx.Client(headers=_headers(cfg["token"], cfg["api_version"]),
                       timeout=cfg["poll_timeout"] + 10,
                       verify=cfg["verify_ssl"]) as client:
        search_id = _submit_search(client, cfg, query, limit)
        _poll_search_status(client, cfg, search_id)
        raw_records = _fetch_results(client, cfg, search_id, limit)

    records = [_normalize_record(r) for r in raw_records[:limit]]
    return {
        "siem_type": "qradar",
        "query": query,
        "record_count": len(records),
        "logs": records,
    }
