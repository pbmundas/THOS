"""Prompt-injection sentinel run before logs reach reasoning-capable agents."""
import re
from services.orchestration.state import HuntState

_MARKERS = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|"
    r"disregard\s+(the\s+)?(system|above)|you\s+are\s+now\s+|"
    r"new\s+instructions?\s*:|(?:system|assistant)\s*:", re.IGNORECASE)


async def guardrail_node(state: HuntState) -> dict:
    """Flag, never delete, suspicious untrusted content for auditable review."""
    hits = []
    records = state.get("processed_logs") or state.get("logs") or []
    for index, record in enumerate(records):
        for field in ("detail", "event", "user", "host"):
            value = record.get(field)
            if isinstance(value, str) and _MARKERS.search(value):
                hits.append({"record_index": index, "field": field, "reason": "instruction-like text in untrusted telemetry"})
    return {"guardrail_result": {"status": "flagged" if hits else "clean", "hits": hits[:100], "scanned_records": len(records)}}
