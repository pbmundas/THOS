import asyncio
import json
import os
import time

from services.mcp.mcp_client import call_tool
from services.observability import cache
from services.orchestration.state import HuntState
from services.hunting.query_generator import validate_and_normalize_query


def _record_identity(record: dict) -> str:
    return json.dumps(
        {
            key: record.get(key)
            for key in ("timestamp", "host", "user", "event", "src_ip", "dst_ip", "detail")
        },
        sort_keys=True,
        default=str,
    )


async def _shared_wazuh_technique_telemetry(state: HuntState, limit: int) -> tuple[list[dict], bool]:
    """Fetch/cache one ATT&CK-tagged Wazuh window shared by related hunts."""
    technique_id = str(state.get("technique_id") or "").strip().upper()
    if not technique_id:
        return [], False
    window_seconds = max(
        60, int(os.environ.get("THOS_TELEMETRY_CACHE_WINDOW_SECONDS", "300"))
    )
    bucket = int(time.time()) // window_seconds
    payload = json.dumps(
        {
            "version": 1,
            "siem": "wazuh",
            "technique_id": technique_id,
            "bucket": bucket,
            "window_seconds": window_seconds,
            "limit": limit,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    cached = await asyncio.to_thread(cache.cache_get, "technique_telemetry", payload)
    if isinstance(cached, dict):
        return list(cached.get("logs") or []), True

    technique_name = str(state.get("technique_name") or "").strip()
    should = [{"term": {"rule.mitre.id": technique_id}}]
    if technique_name:
        should.append({"match_phrase": {"rule.mitre.technique": technique_name}})
    query = json.dumps(
        {"query": {"bool": {"should": should, "minimum_should_match": 1}}},
        separators=(",", ":"),
    )
    result = await call_tool(
        "fetch_siem_logs",
        {"query": query, "limit": limit, "siem_type": "wazuh"},
    )
    if not result.get("error"):
        await asyncio.to_thread(
            cache.cache_set,
            "technique_telemetry",
            payload,
            result,
            window_seconds,
        )
    return list(result.get("logs") or []), False


async def fetch_logs_node(state: HuntState) -> dict:
    siem_type = state.get("siem_type", "folder")
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
    limit = state.get("log_limit") or (1000 if siem_type in
                                        ("folder", "local_folder", "file", "local") else 25)
    executed = list(state.get("executed_queries") or [])
    # A model occasionally asks to repeat the same query verbatim. Do not
    # spend another full SOC/reasoning pass on identical telemetry.
    if query and query in executed:
        return {"follow_up_query": None, "need_more_logs": False, "executed_queries": executed}
    fetch_call = call_tool("fetch_siem_logs", {
        "query": query,
        "limit": limit,
        "siem_type": siem_type,
        "log_source_path": state.get("log_source_path", "") or "",
    })
    if str(siem_type).lower() == "wazuh":
        result, (shared_logs, telemetry_cache_hit) = await asyncio.gather(
            fetch_call,
            _shared_wazuh_technique_telemetry(state, int(limit)),
        )
    else:
        result = await fetch_call
        shared_logs, telemetry_cache_hit = [], False
    if result.get("error"):
        raise RuntimeError(f"{siem_type} log fetch failed: {result['error']}")
    existing = state.get("logs", []) or []
    new_logs = list(result.get("logs", []) or [])
    seen = {_record_identity(item) for item in new_logs}
    for record in shared_logs:
        identity = _record_identity(record)
        if identity not in seen:
            new_logs.append(record)
            seen.add(identity)
    if query:
        executed.append(query)
    return {
        "query": query if not state.get("follow_up_query") else state.get("query", ""),
        "logs": existing + new_logs,
        "record_count": result.get("record_count", 0),
        "total_hits": result.get("total_hits"),
        "follow_up_query": None,
        "executed_queries": executed,
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
        "technique_telemetry_records": len(shared_logs),
    }
