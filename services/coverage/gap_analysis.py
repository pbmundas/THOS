from collections import Counter
from services.orchestration.state import HuntState


async def coverage_gap_node(state: HuntState) -> dict:
    logs = state.get("processed_logs") or []
    events = Counter(str(log.get("event", "unknown")) for log in logs)
    gaps = []
    if state.get("used_fallback_unfiltered"):
        gaps.append("The generated query matched no records; analysis used unfiltered telemetry and should be scoped again.")
    if len(logs) < 10:
        gaps.append(f"Only {len(logs)} normalized record(s) reached analysis; absence conclusions are low confidence.")
    if not events:
        gaps.append("No normalized event types were available; validate collector ingestion and parser support.")
    if state.get("files_scanned") == 0:
        gaps.append("No log files were scanned; verify the selected folder path and allowed roots.")
    return {"coverage_gaps": gaps}
