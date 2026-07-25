from services.detection.alert_triage import triage_detection
from services.detection import sigma_detection_agent


def _memory_cache(monkeypatch):
    values = {}
    monkeypatch.setattr(
        sigma_detection_agent.cache,
        "cache_get",
        lambda namespace, payload: values.get((namespace, payload)),
    )
    monkeypatch.setattr(
        sigma_detection_agent.cache,
        "cache_set",
        lambda namespace, payload, value, ttl: values.__setitem__((namespace, payload), value),
    )


def test_recurring_hits_are_suppressed_between_runs(monkeypatch):
    _memory_cache(monkeypatch)
    event = {
        "timestamp": "2026-07-25T10:15:00Z",
        "host": "host-01",
        "user": "analyst",
        "event": "process_creation",
        "detail": "powershell.exe -enc ...",
    }

    first, first_stats = sigma_detection_agent.deduplicate_recurring_hits(
        "rule-1", "splunk", [event], schedule_id="schedule-1"
    )
    second, second_stats = sigma_detection_agent.deduplicate_recurring_hits(
        "rule-1", "splunk", [event], schedule_id="schedule-1"
    )

    assert first == [event]
    assert first_stats["duplicates_suppressed"] == 0
    assert second == []
    assert second_stats["duplicates_suppressed"] == 1


def test_triage_uses_sigma_metadata_without_an_llm():
    triage = triage_detection({
        "rule_id": "rule-1",
        "rule_title": "Suspicious PowerShell",
        "level": "high",
        "siem_type": "wazuh",
        "events_matched": 2,
        "tags": ["attack.t1059.001"],
    })

    assert triage["priority"] == "high"
    assert triage["technique_id"] == "T1059.001"
    assert triage["method"] == "deterministic_sigma_metadata"

