from services.orchestration.state import HuntState
from services.siem.attribution import attribute_record, telemetry_profile


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
        key = (
            log.get("timestamp"),
            log.get("host"),
            log.get("user"),
            log.get("event"),
            log.get("src_ip"),
            log.get("dst_ip"),
            log.get("src_port"),
            log.get("dst_port"),
            log.get("protocol"),
            str(log.get("detail") or "")[:1000],
            log.get("source_type"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(log)

    attributed = [
        attribute_record(
            log,
            str(
                log.get("collector")
                or log.get("source_type")
                or state.get("active_query_source")
                or state.get("siem_type")
                or ""
            ),
        )
        for log in deduped
    ]
    return {
        "processed_logs": attributed,
        "telemetry_profile": telemetry_profile(attributed),
    }
