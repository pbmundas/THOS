from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState
from services.hunting.query_generator import validate_and_normalize_query


async def fetch_logs_node(state: HuntState) -> dict:
    siem_type = state.get("siem_type", "mock")
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
    result = await call_tool("fetch_siem_logs", {
        "query": query,
        "limit": limit,
        "siem_type": siem_type,
        "log_source_path": state.get("log_source_path", "") or "",
    })
    if result.get("error"):
        raise RuntimeError(f"{siem_type} log fetch failed: {result['error']}")
    existing = state.get("logs", []) or []
    new_logs = result.get("logs", [])
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
    }
