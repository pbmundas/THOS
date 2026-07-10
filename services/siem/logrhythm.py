"""
LogRhythm SIEM connector — Phase 2 real implementation.

Talks to the LogRhythm Web Console **Search API** (the REST API used to
query the Web Indexer for logs/events), using the documented two-step
async pattern:

    1. POST {base_url}/actions/search-task     -> submit a search, get a TaskId back
    2. POST {base_url}/actions/search-result    -> poll with that TaskId until the
                                                    task status shows the search is
                                                    complete, then read the results
                                                    out of the same response

Reference: https://developers.exabeam.com/logrhythm-siem/ (LogRhythm's API docs
were migrated here after the Exabeam/LogRhythm merger). The Search API listens
on port 8505 by default (distinct from the Admin API on 8501), e.g.
``https://<platform-manager-host>:8505/lr-search-api``.

Configuration (see env.example):
    LOGRHYTHM_BASE_URL       e.g. https://logrhythm.example.com:8505/lr-search-api
    LOGRHYTHM_API_TOKEN      Bearer token for an API Account (Client Console ->
                             API accounts). Sent as `Authorization: Bearer <token>`.
    LOGRHYTHM_VERIFY_SSL     "0" to disable TLS verification (self-signed PM certs
                             are common in on-prem labs). Defaults to "1".
    LOGRHYTHM_LOOKBACK_MINUTES   Search window size, default 1440 (24h).
    LOGRHYTHM_POLL_INTERVAL_SECONDS  Delay between result polls, default 2.
    LOGRHYTHM_POLL_TIMEOUT_SECONDS   Give up waiting for completion after this
                             many seconds, default 60 (matches the API's own
                             default `queryTimeout`).
    LOGRHYTHM_SEARCH_EVENTS  "1" to search AIE Events instead of raw Logs
                             (`queryEventManager`). Defaults to "0" (logs).

Known caveats / things to verify against your specific LogRhythm version
before relying on this in production:
  - `queryFilter` schema below covers the common "single free-text or
    field:value filter" case. LogRhythm's full filter grammar (nested
    filter groups, per-field operators, list-based filters, etc.) is much
    richer — extend `_build_query_filter` if your hunts need it.
  - The exact set of field names LogRhythm returns on a log/event record
    can vary with your Knowledge Base / classification config, so
    `_normalize_record` tries several common aliases per field rather than
    assuming one fixed schema.
"""
from __future__ import annotations

import os
import time
import datetime
import logging
from typing import Any

import httpx

from services.observability.retry import sync_retry

logger = logging.getLogger(__name__)


class LogRhythmConfigError(RuntimeError):
    """Raised when required LogRhythm connection settings are missing."""


class LogRhythmAPIError(RuntimeError):
    """Raised when the LogRhythm Search API returns an error or unexpected shape."""


def _get_config() -> dict:
    base_url = os.environ.get("LOGRHYTHM_BASE_URL", "").rstrip("/")
    token = os.environ.get("LOGRHYTHM_API_TOKEN", "")
    if not base_url or not token:
        raise LogRhythmConfigError(
            "LogRhythm is not configured. Set LOGRHYTHM_BASE_URL "
            "(e.g. https://<platform-manager>:8505/lr-search-api) and "
            "LOGRHYTHM_API_TOKEN in the environment (see env.example)."
        )
    return {
        "base_url": base_url,
        "token": token,
        "verify_ssl": os.environ.get("LOGRHYTHM_VERIFY_SSL", "1") != "0",
        "lookback_minutes": int(os.environ.get("LOGRHYTHM_LOOKBACK_MINUTES", "1440")),
        "poll_interval": float(os.environ.get("LOGRHYTHM_POLL_INTERVAL_SECONDS", "2")),
        "poll_timeout": float(os.environ.get("LOGRHYTHM_POLL_TIMEOUT_SECONDS", "60")),
        "search_events": os.environ.get("LOGRHYTHM_SEARCH_EVENTS", "0") == "1",
    }


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _build_date_criteria(lookback_minutes: int) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=lookback_minutes)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return {
        "useInsertedDate": False,
        "dateMin": start.strftime(fmt),
        "dateMax": now.strftime(fmt),
    }


def _build_query_filter(query: str) -> dict:
    """
    Translate a query string (as produced by generate_siem_query for
    siem_type="logrhythm") into a LogRhythm queryFilter object.

    Supports simple `field:"value"` / `field:value` tokens joined by
    whitespace or `AND` (all treated as AND'd filter items), falling back
    to a full-text "Contains" filter on the log message when no
    `field:value` tokens are present.
    """
    query = (query or "").strip()
    tokens = []
    if query:
        for raw_tok in query.replace(" AND ", " ").split():
            if ":" in raw_tok:
                field, _, value = raw_tok.partition(":")
                value = value.strip('"').strip("'")
                if field and value:
                    tokens.append((field, value))

    if not tokens:
        return {
            "filterGroup": {
                "filterItemType": "Group",
                "fieldOperator": "And",
                "filterGroupOperator": "And",
                "filterItems": [
                    {
                        "filterItemType": "MessageFilter",
                        "fieldOperator": "Contains",
                        "values": [{"value": query}] if query else [],
                    }
                ],
            }
        }

    return {
        "filterGroup": {
            "filterItemType": "Group",
            "fieldOperator": "And",
            "filterGroupOperator": "And",
            "filterItems": [
                {
                    "filterItemType": "FieldFilter",
                    "fieldName": field,
                    "fieldOperator": "IsEqual",
                    "values": [{"value": value}],
                }
                for field, value in tokens
            ],
        }
    }


def _submit_search_task(client: httpx.Client, cfg: dict, query: str, limit: int) -> str:
    body = {
        "maxMsgsToQuery": limit,
        "queryTimeout": int(cfg["poll_timeout"]),
        "searchMode": 3,  # PagedSortedDateDesc — newest logs first
        "dateCriteria": _build_date_criteria(cfg["lookback_minutes"]),
        "queryLogSources": [],
        "logSourceIds": [],
        "queryFilter": _build_query_filter(query),
        "queryEventManager": cfg["search_events"],
    }
    resp = sync_retry(
        client.post, f"{cfg['base_url']}/actions/search-task", json=body,
        what="logrhythm submit search-task",
    )
    if resp.status_code >= 400:
        raise LogRhythmAPIError(
            f"search-task failed: HTTP {resp.status_code} — {resp.text[:500]}"
        )
    data = resp.json()
    task_id = data.get("TaskId") or data.get("taskId") or data.get("searchGUID")
    if not task_id:
        raise LogRhythmAPIError(f"search-task returned no TaskId: {data}")
    return task_id


def _extract_records(payload: Any) -> list[dict] | None:
    """Pull the list of raw log/event dicts out of a search-result
    response, trying the handful of shapes LogRhythm's API is known to
    use across versions. Returns None if this payload doesn't look like
    it contains a (possibly empty) result list yet."""
    if not isinstance(payload, dict):
        return None
    for key in ("results", "Results", "events", "Events", "logs", "searchResults"):
        val = payload.get(key)
        if isinstance(val, list):
            return val
    data = payload.get("data")
    if isinstance(data, dict):
        return _extract_records(data)
    if isinstance(data, list):
        return data
    return None


def _is_complete(payload: dict) -> bool:
    status_text = " ".join(
        str(payload.get(k, ""))
        for k in ("TaskStatus", "taskStatus", "statusmessage", "statusMessage", "responsemessage")
    ).upper()
    if "COMPLETED" in status_text or "NO RESULTS" in status_text:
        return True
    # Some deployments just return the results list directly once ready,
    # with no explicit "completed" status string.
    return _extract_records(payload) is not None and status_text == ""


def _poll_search_result(client: httpx.Client, cfg: dict, task_id: str) -> list[dict]:
    body = {"data": {"search": {"searchGUID": task_id}}}
    deadline = time.monotonic() + cfg["poll_timeout"]

    while True:
        resp = sync_retry(
            client.post, f"{cfg['base_url']}/actions/search-result", json=body,
            what="logrhythm poll search-result",
        )
        if resp.status_code >= 400:
            raise LogRhythmAPIError(
                f"search-result failed: HTTP {resp.status_code} — {resp.text[:500]}"
            )
        payload = resp.json()

        if _is_complete(payload):
            return _extract_records(payload) or []

        if time.monotonic() >= deadline:
            logger.warning(
                "LogRhythm search task %s did not complete within %ss; "
                "returning partial/empty results.", task_id, cfg["poll_timeout"],
            )
            return _extract_records(payload) or []

        time.sleep(cfg["poll_interval"])


def _pick(raw: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        val = raw.get(key)
        if val not in (None, ""):
            return str(val)
    return default


def _normalize_record(raw: dict) -> dict:
    """Map a raw LogRhythm log/event dict onto THOS's common log schema
    (timestamp/host/user/event/detail/src_ip) — the same shape produced
    by mock mode and file_log_parser, so downstream nodes don't need to
    know which SIEM the data came from."""
    return {
        "timestamp": _pick(raw, "normalDate", "normalDateMin", "originDateFormatted",
                            "dateInserted", "NormalDate"),
        "host": _pick(raw, "impactedName", "hostName", "originHostName",
                      "impactedHostName", "entityName"),
        "user": _pick(raw, "login", "loginName", "account", "subject"),
        "event": _pick(raw, "commonEventName", "classificationName",
                        "vendorMessageId", default="event"),
        "detail": _pick(raw, "message", "logMessage", "object", "command"),
        "src_ip": _pick(raw, "originIP", "sourceIP", "srcIP", "originIp"),
        "_raw": raw,
    }


def fetch_logs(query: str, limit: int = 25, **_ignored) -> dict:
    """
    Entry point dispatched from siem_connector.fetch_logs when
    siem_type == "logrhythm". Synchronous (uses httpx.Client) so it can
    be called directly from the sync `fetch_siem_logs` MCP tool without
    any event-loop juggling.
    """
    cfg = _get_config()

    with httpx.Client(headers=_headers(cfg["token"]), timeout=cfg["poll_timeout"] + 10,
                       verify=cfg["verify_ssl"]) as client:
        task_id = _submit_search_task(client, cfg, query, limit)
        raw_records = _poll_search_result(client, cfg, task_id)

    records = [_normalize_record(r) for r in raw_records[:limit]]
    return {
        "siem_type": "logrhythm",
        "query": query,
        "record_count": len(records),
        "logs": records,
    }
