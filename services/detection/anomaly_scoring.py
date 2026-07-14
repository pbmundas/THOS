"""Lightweight behavioural rarity scoring over normalized hunt telemetry."""
from collections import Counter


def score_rare_events(logs: list[dict]) -> list[dict]:
    counts = Counter(str(log.get("event", "unknown")) for log in logs)
    threshold = max(1, len(logs) // 20)  # rarest ~5%, with a minimum of one
    return [
        {"record_index": index, "event": str(log.get("event", "unknown")), "event_count": counts[str(log.get("event", "unknown"))], "reason": "rare event type in this hunt"}
        for index, log in enumerate(logs)
        if counts[str(log.get("event", "unknown"))] <= threshold
    ][:100]
