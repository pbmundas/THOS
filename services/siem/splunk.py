"""
Splunk SIEM connector — Phase 2 real implementation.

Talks to the Splunk Enterprise/Cloud **REST Search API** (management
port, default 8089), using the documented async search-job pattern:

    1. POST {base_url}/services/search/jobs
                                    -> submit an SPL search, get a
                                       search id (sid) back
    2. GET  {base_url}/services/search/jobs/{sid}
                                    -> poll until dispatchState is DONE
                                       (or FAILED)
    3. GET  {base_url}/services/search/jobs/{sid}/results
                                    -> retrieve results (JSON output mode)

Reference: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch

Configuration (see env.example):
    SPLUNK_BASE_URL       e.g. https://splunk.example.com:8089
    SPLUNK_TOKEN          Splunk auth token (Settings -> Tokens, or a
                           bearer token from `splunk auth login`). Sent
                           as `Authorization: Bearer <token>`.
    SPLUNK_VERIFY_SSL     "0" to disable TLS verification (self-signed
                           certs are common in on-prem labs). Defaults
                           to "1".
    SPLUNK_LOOKBACK       Time modifier for `earliest_time`, default
                           "-24h" (Splunk relative time syntax).
    SPLUNK_POLL_INTERVAL_SECONDS  Delay between job-status polls,
                           default 2.
    SPLUNK_POLL_TIMEOUT_SECONDS   Give up waiting for the job to finish
                           after this many seconds, default 60.

The query string handed in here is expected to already be a valid SPL
search (query_generator.py prompts the LLM to produce SPL directly for
siem_type="splunk", grounded in the field mapping from siem_kb.py) —
this module does not build or rewrite SPL, it just runs it.

Known caveats / things to verify against your specific Splunk version
before relying on this in production:
  - Assumes the caller's SPL already starts with `search` (or is a
    generating command like `| tstats` / `| pivot`); a bare filter
    expression is prefixed with `search ` for convenience.
  - `_normalize_record` tries several common CIM/notable-event field
    aliases per field rather than assuming one fixed schema, since the
    fields actually present depend heavily on the source's CIM
    compliance and any `eval`/`rename` in the SPL itself.
"""
from __future__ import annotations

import os
import time
import logging
from typing import Any

import httpx

from services.observability.retry import sync_retry

logger = logging.getLogger(__name__)


class SplunkConfigError(RuntimeError):
    """Raised when required Splunk connection settings are missing."""


class SplunkAPIError(RuntimeError):
    """Raised when the Splunk Search API returns an error or unexpected shape."""


def _get_config() -> dict:
    base_url = os.environ.get("SPLUNK_BASE_URL", "").rstrip("/")
    token = os.environ.get("SPLUNK_TOKEN", "")
    if not base_url or not token:
        raise SplunkConfigError(
            "Splunk is not configured. Set SPLUNK_BASE_URL "
            "(e.g. https://<splunk-host>:8089) and SPLUNK_TOKEN in the "
            "environment (see env.example)."
        )
    return {
        "base_url": base_url,
        "token": token,
        "verify_ssl": os.environ.get("SPLUNK_VERIFY_SSL", "1") != "0",
        "lookback": os.environ.get("SPLUNK_LOOKBACK", "-24h"),
        "poll_interval": float(os.environ.get("SPLUNK_POLL_INTERVAL_SECONDS", "2")),
        "poll_timeout": float(os.environ.get("SPLUNK_POLL_TIMEOUT_SECONDS", "60")),
    }


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _normalize_spl(query: str) -> str:
    """Ensure the SPL starts with a generating command. A search that's
    just a bare filter (e.g. `index=main sourcetype=wineventlog`) needs
    an explicit leading `search`; generating commands (`| tstats`,
    `| pivot`, `| datamodel`, etc.) or one already starting with
    `search` are left untouched."""
    q = (query or "").strip()
    if not q:
        return "search *"
    if q.startswith("|") or q.lower().startswith("search "):
        return q
    return f"search {q}"


def _submit_search_job(client: httpx.Client, cfg: dict, query: str, limit: int) -> str:
    data = {
        "search": _normalize_spl(query),
        "earliest_time": cfg["lookback"],
        "latest_time": "now",
        "output_mode": "json",
        "count": limit,
        "max_count": limit,
    }
    resp = sync_retry(
        client.post, f"{cfg['base_url']}/services/search/jobs", data=data,
        what="splunk submit search job",
    )
    if resp.status_code >= 400:
        raise SplunkAPIError(
            f"search job submit failed: HTTP {resp.status_code} — {resp.text[:500]}"
        )
    payload = resp.json()
    sid = payload.get("sid")
    if not sid:
        raise SplunkAPIError(f"search job submit returned no sid: {payload}")
    return sid


def _poll_job_status(client: httpx.Client, cfg: dict, sid: str) -> None:
    """Poll the job's status endpoint until dispatchState is DONE (or
    FAILED, which raises). Times out silently (job may still be running
    in Splunk) so the caller can fall back to whatever partial results
    the results endpoint is willing to return."""
    deadline = time.monotonic() + cfg["poll_timeout"]
    url = f"{cfg['base_url']}/services/search/jobs/{sid}"

    while True:
        resp = sync_retry(
            client.get, url, params={"output_mode": "json"},
            what="splunk poll job status",
        )
        if resp.status_code >= 400:
            raise SplunkAPIError(
                f"job status check failed: HTTP {resp.status_code} — {resp.text[:500]}"
            )
        payload = resp.json()
        content = (payload.get("entry") or [{}])[0].get("content", {})
        state = content.get("dispatchState", "")

        if state == "DONE":
            return
        if state == "FAILED":
            messages = content.get("messages", [])
            raise SplunkAPIError(f"search job {sid} failed: {messages}")

        if time.monotonic() >= deadline:
            logger.warning(
                "Splunk search job %s did not finish within %ss "
                "(last state=%s); attempting to read partial results.",
                sid, cfg["poll_timeout"], state,
            )
            return

        time.sleep(cfg["poll_interval"])


def _fetch_results(client: httpx.Client, cfg: dict, sid: str, limit: int) -> list[dict]:
    resp = sync_retry(
        client.get, f"{cfg['base_url']}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": limit},
        what="splunk fetch results",
    )
    if resp.status_code >= 400:
        raise SplunkAPIError(
            f"results fetch failed: HTTP {resp.status_code} — {resp.text[:500]}"
        )
    payload = resp.json()
    results = payload.get("results", [])
    return results if isinstance(results, list) else []


def _pick(raw: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        val = raw.get(key)
        if val not in (None, ""):
            return str(val)
    return default


def _normalize_record(raw: dict) -> dict:
    """Map a raw Splunk result dict onto THOS's common log schema
    (timestamp/host/user/event/detail/src_ip) — the same shape produced
    by mock mode, file_log_parser, and the LogRhythm connector, so
    downstream nodes don't need to know which SIEM the data came from."""
    return {
        "timestamp": _pick(raw, "_time", "timestamp"),
        "host": _pick(raw, "host", "dest", "Computer"),
        "user": _pick(raw, "user", "User", "Account_Name", "src_user"),
        "event": _pick(raw, "sourcetype", "signature", "EventCode", "event_type",
                        default="event"),
        "detail": _pick(raw, "_raw", "message", "CommandLine"),
        "src_ip": _pick(raw, "src_ip", "src", "Source_Network_Address"),
        "_raw": raw,
    }


def fetch_logs(query: str, limit: int = 25, **_ignored) -> dict:
    """
    Entry point dispatched from siem_connector.fetch_logs when
    siem_type == "splunk". Synchronous (uses httpx.Client) so it can be
    called directly from the sync `fetch_siem_logs` MCP tool without any
    event-loop juggling — same shape as logrhythm.fetch_logs.
    """
    cfg = _get_config()

    with httpx.Client(headers=_headers(cfg["token"]), timeout=cfg["poll_timeout"] + 10,
                       verify=cfg["verify_ssl"]) as client:
        sid = _submit_search_job(client, cfg, query, limit)
        _poll_job_status(client, cfg, sid)
        raw_records = _fetch_results(client, cfg, sid, limit)

    records = [_normalize_record(r) for r in raw_records[:limit]]
    return {
        "siem_type": "splunk",
        "query": query,
        "record_count": len(records),
        "logs": records,
    }
