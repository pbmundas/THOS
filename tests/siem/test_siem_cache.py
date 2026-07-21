import asyncio

from services.siem import siem_connector
from services.siem import siem_fetch


def test_mock_fetch_is_cached_for_repeated_query(monkeypatch):
    values = {}
    generated = 0

    monkeypatch.setattr(
        siem_connector.cache, "cache_get",
        lambda namespace, payload: values.get((namespace, payload)),
    )
    monkeypatch.setattr(
        siem_connector.cache, "cache_set",
        lambda namespace, payload, value: values.__setitem__((namespace, payload), value),
    )

    def fake_logs(query, limit):
        nonlocal generated
        generated += 1
        return [{"event": "stable"}]

    monkeypatch.setattr(siem_connector, "_mock_logs", fake_logs)

    first = siem_connector.fetch_logs("same query", 25, "mock")
    second = siem_connector.fetch_logs("same query", 25, "mock")

    assert first == second
    assert generated == 1


def test_cache_key_includes_source_configuration(monkeypatch):
    monkeypatch.setenv("SPLUNK_BASE_URL", "https://tenant-a")
    first = siem_connector._cache_payload("splunk", "index=main", 25)
    monkeypatch.setenv("SPLUNK_BASE_URL", "https://tenant-b")
    second = siem_connector._cache_payload("splunk", "index=main", 25)

    assert first != second


def test_follow_up_query_is_validated_immediately_before_siem_call(monkeypatch):
    captured = {}

    async def fake_call_tool(name, payload):
        captured.update(payload)
        return {"record_count": 0, "logs": []}

    monkeypatch.setattr(siem_fetch, "call_tool", fake_call_tool)
    result = asyncio.run(siem_fetch.fetch_logs_node({
        "siem_type": "qradar",
        "hypothesis_text": "PowerShell activity",
        "query": "SELECT sourceip FROM events",
        "follow_up_query": "DROP TABLE events",
        "executed_queries": ["SELECT sourceip FROM events"],
    }))

    assert captured["query"] == "SELECT * FROM events"
    assert result["query_used_fallback"] is True
    assert "complete SELECT" in result["query_validation_error"]
