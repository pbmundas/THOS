import asyncio
import json
import os
import time

from services.mcp.mcp_client import call_tool
from services.observability import cache
from services.orchestration.state import HuntState
from services.hunting.query_generator import validate_and_normalize_query
from services.runtime_config import env_or_runtime, get_value


def _record_identity(record: dict) -> str:
    return json.dumps(
        {
            key: record.get(key)
            for key in ("timestamp", "host", "user", "event", "src_ip", "dst_ip", "detail")
        },
        sort_keys=True,
        default=str,
    )


def _default_lookback_minutes(siem_type: str) -> int:
    source = str(siem_type or "").lower()
    setting_name = {
        "wazuh": "WAZUH_LOOKBACK_MINUTES",
        "elasticsearch": "ELASTICSEARCH_LOOKBACK_MINUTES",
        "qradar": "QRADAR_LOOKBACK_MINUTES",
        "logrhythm": "LOGRHYTHM_LOOKBACK_MINUTES",
    }.get(source)
    if setting_name:
        try:
            return max(1, int(env_or_runtime(setting_name, source, "1440")))
        except (TypeError, ValueError):
            return 1440
    if source == "splunk":
        raw = str(env_or_runtime("SPLUNK_LOOKBACK", source, "-24h")).strip().lower()
        try:
            if raw.startswith("-") and raw.endswith("h"):
                return max(1, int(float(raw[1:-1]) * 60))
            if raw.startswith("-") and raw.endswith("m"):
                return max(1, int(float(raw[1:-1])))
        except ValueError:
            pass
    return 1440


def _attempt_key(source: str, query: str, lookback: int, limit: int) -> str:
    return json.dumps(
        {
            "source": source,
            "query": query,
            "lookback_minutes": lookback,
            "limit": limit,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


async def _shared_technique_telemetry(
    state: HuntState,
    source: str,
    query: str,
    limit: int,
    lookback_minutes: int,
    log_source_path: str,
) -> tuple[dict, bool]:
    """Fetch/cache a validated source query for related technique hunts.

    The query remains source-specific and agent-generated. The cache contract
    is integration-neutral and never manufactures a vendor query.
    """
    technique_id = str(state.get("technique_id") or "").strip().upper()
    window_seconds = max(
        60, int(os.environ.get("THOS_TELEMETRY_CACHE_WINDOW_SECONDS", "300"))
    )
    bucket = int(time.time()) // window_seconds
    payload = json.dumps(
        {
            "version": 2,
            "siem": source,
            "technique_id": technique_id,
            "bucket": bucket,
            "window_seconds": window_seconds,
            "query": query,
            "limit": limit,
            "lookback_minutes": lookback_minutes,
            "log_source_path": log_source_path,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    cached = await asyncio.to_thread(cache.cache_get, "technique_telemetry", payload)
    if isinstance(cached, dict):
        return cached, True
    result = await call_tool(
        "fetch_siem_logs",
        {
            "query": query,
            "limit": limit,
            "siem_type": source,
            "log_source_path": log_source_path,
            "lookback_minutes": lookback_minutes,
        },
    )
    if not result.get("error"):
        await asyncio.to_thread(
            cache.cache_set,
            "technique_telemetry",
            payload,
            result,
            window_seconds,
        )
    return result, False


async def fetch_logs_node(state: HuntState) -> dict:
    siem_type = str(
        state.get("follow_up_source")
        or state.get("active_query_source")
        or state.get("siem_type", "folder")
    ).lower()
    requested_query = state.get("follow_up_query") or state.get("query", "")
    validation = validate_and_normalize_query(
        requested_query, state.get("hypothesis_text", "") or "", siem_type,
    )
    query = validation["query"]
    # Folder-backed sources typically hold far more records than a
    # hand-tuned mock/live query, so give them a larger default cap.
    # Bumped from 200 -> 1000: with EVTX exports especially, a handful
    # of hundred noise events (4663/5156/4799 etc.) can easily crowd out
    # the rare event you actually care about (e.g. 4104 PowerShell
    # script block logging) if the cap is too tight.
    folder_default = int(
        get_value("autonomy", "default_folder_query_limit", default=1000)
    )
    live_default = int(
        get_value("autonomy", "default_live_query_limit", default=100)
    )
    limit = int(
        state.get("follow_up_limit")
        or state.get("active_query_limit")
        or state.get("log_limit")
        or (
            folder_default
            if siem_type in ("folder", "local_folder", "file", "local")
            else live_default
        )
    )
    lookback_minutes = int(
        state.get("follow_up_lookback_minutes")
        or state.get("active_lookback_minutes")
        or _default_lookback_minutes(siem_type)
    )
    objective = str(
        state.get("follow_up_objective")
        or state.get("active_query_objective")
        or "Retrieve direct evidence supporting or refuting the hypothesis."
    )
    executed = list(state.get("executed_queries") or [])
    executed_keys = list(state.get("executed_query_keys") or [])
    retrieval_attempts = list(state.get("retrieval_attempts") or [])
    source_diagnostics = dict(state.get("source_diagnostics") or {})
    if not query:
        reason = (
            validation["validation_error"]
            or state.get("query_validation_error")
            or "Query Generation Agent did not return a validated query."
        )
        retrieval_attempts.append({
            "sequence": len(retrieval_attempts) + 1,
            "source": siem_type,
            "objective": objective,
            "query": requested_query,
            "normalized_query": "",
            "lookback_minutes": lookback_minutes,
            "limit": limit,
            "status": "query_generation_failed",
            "record_count": 0,
            "total_hits": None,
            "validation_error": reason,
        })
        source_diagnostics[siem_type] = {
            "status": "query_generation_failed",
            "last_record_count": 0,
            "last_total_hits": None,
            "last_lookback_minutes": lookback_minutes,
            "last_limit": limit,
            "error": reason,
            "attempt_count": sum(
                attempt.get("source") == siem_type
                for attempt in retrieval_attempts
            ),
        }
        return {
            "logs": list(state.get("logs") or []),
            "record_count": len(state.get("logs") or []),
            "last_record_count": 0,
            "last_total_hits": None,
            "active_query_source": siem_type,
            "active_query": "",
            "active_query_objective": objective,
            "active_lookback_minutes": lookback_minutes,
            "active_query_limit": limit,
            "follow_up_query": None,
            "follow_up_source": None,
            "follow_up_lookback_minutes": None,
            "follow_up_limit": None,
            "follow_up_objective": None,
            "need_more_logs": False,
            "executed_queries": executed,
            "executed_query_keys": executed_keys,
            "retrieval_attempts": retrieval_attempts,
            "source_diagnostics": source_diagnostics,
            "query_used_fallback": True,
            "query_validation_error": reason,
        }
    attempt_key = _attempt_key(siem_type, query, lookback_minutes, limit)
    # A model occasionally asks to repeat the same query verbatim. Do not
    # spend another full SOC/reasoning pass on identical telemetry.
    if query and attempt_key in executed_keys:
        retrieval_attempts.append({
            "sequence": len(retrieval_attempts) + 1,
            "source": siem_type,
            "objective": objective,
            "query": requested_query,
            "normalized_query": query,
            "lookback_minutes": lookback_minutes,
            "limit": limit,
            "status": "skipped_duplicate",
            "validation_error": validation["validation_error"],
        })
        return {
            "follow_up_query": None,
            "follow_up_source": None,
            "follow_up_lookback_minutes": None,
            "follow_up_limit": None,
            "follow_up_objective": None,
            "need_more_logs": False,
            "last_record_count": 0,
            "last_total_hits": 0,
            "executed_queries": executed,
            "executed_query_keys": executed_keys,
            "retrieval_attempts": retrieval_attempts,
        }
    result, telemetry_cache_hit = await _shared_technique_telemetry(
        state,
        siem_type,
        query,
        int(limit),
        lookback_minutes,
        state.get("log_source_path", "") or "",
    )
    existing = state.get("logs", []) or []
    new_logs = list(result.get("logs", []) or [])
    for record in new_logs:
        if isinstance(record, dict):
            record.setdefault("collector", siem_type)
            record.setdefault("source_type", siem_type)
    if query:
        executed.append(query)
        executed_keys.append(attempt_key)
    result_error = str(result.get("error") or "")
    attempt_status = "error" if result_error else "executed"
    retrieval_attempts.append({
        "sequence": len(retrieval_attempts) + 1,
        "source": siem_type,
        "objective": objective,
        "query": requested_query,
        "normalized_query": query,
        "lookback_minutes": lookback_minutes,
        "limit": limit,
        "status": attempt_status,
        "record_count": int(result.get("record_count") or 0),
        "total_hits": result.get("total_hits"),
        "used_fallback": validation["used_fallback"],
        "validation_error": validation["validation_error"],
        "error": result_error or None,
        "telemetry_cache_hit": telemetry_cache_hit,
        "technique_telemetry_records": len(new_logs),
    })
    source_diagnostics[siem_type] = {
        "status": "unavailable" if result_error else "queried",
        "last_record_count": int(result.get("record_count") or 0),
        "last_total_hits": result.get("total_hits"),
        "last_lookback_minutes": lookback_minutes,
        "last_limit": limit,
        "error": result_error or None,
        "attempt_count": sum(
            attempt.get("source") == siem_type
            for attempt in retrieval_attempts
        ),
    }
    cumulative_logs = existing + new_logs
    prior_total_hits = int(state.get("total_hits") or 0)
    current_total_hits = result.get("total_hits")
    cumulative_total_hits = (
        prior_total_hits + int(current_total_hits or 0)
        if current_total_hits is not None
        else prior_total_hits or None
    )
    return {
        "query": query if not state.get("follow_up_query") else state.get("query", ""),
        "logs": cumulative_logs,
        "record_count": len(cumulative_logs),
        "total_hits": cumulative_total_hits,
        "last_record_count": int(result.get("record_count") or 0),
        "last_total_hits": result.get("total_hits"),
        "follow_up_query": None,
        "follow_up_source": None,
        "follow_up_lookback_minutes": None,
        "follow_up_limit": None,
        "follow_up_objective": None,
        "active_query_source": siem_type,
        "active_query": query,
        "active_query_objective": objective,
        "active_lookback_minutes": lookback_minutes,
        "active_query_limit": limit,
        "executed_queries": executed,
        "executed_query_keys": executed_keys,
        "retrieval_attempts": retrieval_attempts,
        "source_diagnostics": source_diagnostics,
        "query_used_fallback": validation["used_fallback"],
        "query_validation_error": validation["validation_error"],
        # Diagnostics from file_log_parser.fetch_from_folder (folder mode
        # only — absent/ignored for mock/live SIEM types) so we can
        # verify, in the final report, exactly how many files/records
        # were actually scanned vs. how many survived the query filter.
        "files_scanned": result.get("files_scanned"),
        "total_parsed": result.get("total_parsed"),
        "used_fallback_unfiltered": result.get("used_fallback_unfiltered"),
        "telemetry_cache_hit": telemetry_cache_hit,
        "technique_telemetry_records": len(new_logs),
        # Connector failures are source-scoped hunt gaps, not graph failures.
        # They remain visible in source_diagnostics and retrieval_attempts so
        # another selected source can still complete the investigation.
        "error": state.get("error") if state.get("reasoning_failed") else None,
    }
