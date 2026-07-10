from services.orchestration.state import HuntState


async def process_logs_node(state: HuntState) -> dict:
    """
    Phase 1: simple normalization/dedup pass.
    Phase 2/4 extension point: add parsing for real vendor log formats
    (EVTX-derived JSON, Syslog CEF/LEEF, etc.), timestamp normalization
    to UTC, and entity extraction (host/user/ip graphs) here.
    """
    logs = state.get("logs", [])
    seen = set()
    deduped = []
    for log in logs:
        key = (log.get("timestamp"), log.get("host"), log.get("user"), log.get("event"))
        if key not in seen:
            seen.add(key)
            deduped.append(log)

    return {"processed_logs": deduped}
