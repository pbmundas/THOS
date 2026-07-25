"""
SIEM connector tool.

Phase 1: mock mode — returns synthetic log records so the whole
pipeline (query -> fetch -> process -> reason -> report) can be
exercised end-to-end without a real SIEM.

Folder mode ("folder"): reads real log artifacts (EVTX, .log, syslog,
CSV, CEF, JSON/ECS, XML, .txt, pcap) from a local directory — see
file_log_parser.py — instead of calling a live SIEM API. This lets a
hunter run a hypothesis against an evidence folder (e.g. logs pulled
from an incident, or exported from a SIEM with no live API access) the
same way they'd run it against a real SIEM.

LogRhythm mode ("logrhythm"): implemented — talks to a real LogRhythm
Web Console Search API using the documented two-step async pattern
(submit -> poll -> retrieve). See logrhythm.py for connection settings
and caveats.

Splunk mode ("splunk"): implemented — talks to a real Splunk Search
REST API using the documented async search-job pattern (submit job ->
poll dispatchState -> retrieve results). See splunk.py for connection
settings and caveats.

QRadar mode ("qradar"): implemented — talks to a real QRadar Ariel
Search REST API using the documented async pattern (submit AQL search
-> poll status -> retrieve results). See qradar.py for connection
settings and caveats.
"""
import os
import random
import datetime
import json

from services.siem import file_log_parser
from services.siem import logrhythm as logrhythm_connector
from services.siem import splunk as splunk_connector
from services.siem import qradar as qradar_connector
from services.siem import wazuh as wazuh_connector
from services.observability import cache
from services.runtime_config import env_or_runtime

# Fallback default if a call doesn't specify siem_type explicitly
# (kept for backward compatibility with any code still relying on the
# container-level env var).
DEFAULT_SIEM_TYPE = os.environ.get("SIEM_TYPE", "mock")
DEFAULT_LOG_SOURCE_DIR = os.environ.get("LOG_SOURCE_DIR", "/data/log_sources")


def _cache_payload(siem_type: str, query: str, limit: int,
                   log_source_path: str = "", trusted_sigma: bool = False) -> str:
    """Build one stable key from every setting that can change results."""
    setting_names = {
        "logrhythm": (
            "LOGRHYTHM_BASE_URL", "LOGRHYTHM_API_TOKEN",
            "LOGRHYTHM_LOOKBACK_MINUTES", "LOGRHYTHM_SEARCH_EVENTS",
        ),
        "splunk": ("SPLUNK_BASE_URL", "SPLUNK_TOKEN", "SPLUNK_LOOKBACK"),
        "qradar": ("QRADAR_BASE_URL", "QRADAR_TOKEN", "QRADAR_LOOKBACK_MINUTES"),
        "wazuh": (
            "WAZUH_INDEXER_URL", "WAZUH_INDEX_SOURCE", "WAZUH_LOOKBACK_MINUTES",
            "WAZUH_MAX_RESULTS", "WAZUH_ALERTS_INDEX", "WAZUH_ARCHIVES_INDEX",
            "WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD",
        ),
    }
    payload = {
        "version": 2,
        "siem_type": siem_type,
        "query": query,
        "limit": limit,
        "log_source_path": log_source_path,
        "trusted_sigma": trusted_sigma,
        "settings": {
            name: env_or_runtime(name, siem_type, "")
            for name in setting_names.get(siem_type, ())
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _cached_fetch(siem_type: str, query: str, limit: int, producer,
                  log_source_path: str = "", trusted_sigma: bool = False,
                  use_cache: bool = True) -> dict:
    if not use_cache:
        return producer()
    payload = _cache_payload(siem_type, query, limit, log_source_path, trusted_sigma)
    cached = cache.cache_get("siem_fetch", payload)
    if cached is not None:
        return cached
    result = producer()
    # Configuration/API errors are intentionally not cached: an operator can
    # fix credentials or connectivity and retry immediately.
    if not result.get("error"):
        cache.cache_set("siem_fetch", payload, result)
    return result


def _mock_logs(query: str, limit: int) -> list[dict]:
    now = datetime.datetime.utcnow()
    sample_users = ["jdoe", "asmith", "svc_backup", "administrator"]
    sample_hosts = ["WKS-2201", "WKS-1187", "SRV-DC01", "SRV-FILE02"]
    logs = []
    for i in range(min(limit, 25)):
        logs.append({
            "timestamp": (now - datetime.timedelta(minutes=i * 3)).isoformat() + "Z",
            "host": random.choice(sample_hosts),
            "user": random.choice(sample_users),
            "event": "process_creation" if i % 2 == 0 else "dns_query",
            "detail": f"synthetic record matching query: {query[:60]}",
            "src_ip": f"10.10.{random.randint(1,254)}.{random.randint(1,254)}",
        })
    return logs


def fetch_logs(query: str, limit: int = 25, siem_type: str | None = None,
                log_source_path: str = "", trusted_sigma: bool = False,
                bypass_cache: bool = False) -> dict:
    """
    Execute a SIEM query and return matching log records.

    - siem_type == "mock": generates synthetic but structurally
      realistic records so downstream nodes (log processing, SOC tools,
      reasoning) can be developed/tested without a live SIEM connection.
    - siem_type == "folder": parses every supported log file under
      `log_source_path` (or LOG_SOURCE_DIR) and returns records matching
      the query.
    - anything else: not yet implemented (Phase 2 real connectors).
    """
    siem_type = (siem_type or DEFAULT_SIEM_TYPE or "mock").lower()

    if siem_type == "mock":
        return _cached_fetch("mock", query, limit, lambda: {
                "siem_type": "mock",
                "query": query,
                "record_count": min(limit, 25),
                "logs": _mock_logs(query, limit),
            }, use_cache=not bypass_cache)

    if siem_type in ("folder", "local_folder", "file", "local"):
        folder = log_source_path or DEFAULT_LOG_SOURCE_DIR
        # cache.py's docstring calls out "repeated SIEM queries" as a
        # target, but nothing called it — re-running the same hypothesis
        # against the same evidence folder redid a full parse-and-filter
        # pass over every file every time. Keyed on everything that
        # determines the result: folder, query, and limit.
        return _cached_fetch(
            "folder", query, limit,
            lambda: file_log_parser.fetch_from_folder(folder, query=query, limit=limit),
            log_source_path=folder,
            use_cache=not bypass_cache,
        )

    if siem_type == "logrhythm":
        try:
            return _cached_fetch(
                "logrhythm", query, limit,
                lambda: logrhythm_connector.fetch_logs(query, limit),
                use_cache=not bypass_cache,
            )
        except logrhythm_connector.LogRhythmConfigError as e:
            # Missing/incomplete config is a caller-fixable setup issue,
            # not a connector bug — surface it clearly instead of a raw
            # stack trace bubbling up through the MCP tool call.
            return {
                "siem_type": "logrhythm",
                "query": query,
                "record_count": 0,
                "logs": [],
                "error": str(e),
            }

    if siem_type == "splunk":
        try:
            return _cached_fetch(
                "splunk", query, limit,
                lambda: splunk_connector.fetch_logs(query, limit),
                use_cache=not bypass_cache,
            )
        except splunk_connector.SplunkConfigError as e:
            # Missing/incomplete config is a caller-fixable setup issue,
            # not a connector bug — surface it clearly instead of a raw
            # stack trace bubbling up through the MCP tool call.
            return {
                "siem_type": "splunk",
                "query": query,
                "record_count": 0,
                "logs": [],
                "error": str(e),
            }

    if siem_type == "qradar":
        try:
            return _cached_fetch(
                "qradar", query, limit,
                lambda: qradar_connector.fetch_logs(query, limit),
                use_cache=not bypass_cache,
            )
        except qradar_connector.QRadarConfigError as e:
            # Missing/incomplete config is a caller-fixable setup issue,
            # not a connector bug — surface it clearly instead of a raw
            # stack trace bubbling up through the MCP tool call.
            return {
                "siem_type": "qradar",
                "query": query,
                "record_count": 0,
                "logs": [],
                "error": str(e),
            }

    if siem_type == "wazuh":
        try:
            return _cached_fetch(
                "wazuh", query, limit,
                lambda: wazuh_connector.fetch_logs(query, limit, trusted_sigma=trusted_sigma),
                trusted_sigma=trusted_sigma,
                use_cache=not bypass_cache,
            )
        except wazuh_connector.WazuhConfigError as e:
            return {
                "siem_type": "wazuh",
                "query": query,
                "record_count": 0,
                "logs": [],
                "error": str(e),
            }

    raise NotImplementedError(
        f"SIEM_TYPE='{siem_type}' is not implemented yet. "
        f"Supported: mock, folder, logrhythm, splunk, qradar, wazuh."
    )
