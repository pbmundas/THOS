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


def test_wazuh_technique_window_is_reused_across_related_hunts(monkeypatch):
    values = {}
    technique_calls = 0
    normal_calls = 0

    monkeypatch.setattr(
        siem_fetch.cache,
        "cache_get",
        lambda namespace, payload: values.get((namespace, payload)),
    )

    def cache_set(namespace, payload, value, ttl=300):
        values[(namespace, payload)] = value

    monkeypatch.setattr(siem_fetch.cache, "cache_set", cache_set)

    async def fake_call_tool(_name, payload):
        nonlocal technique_calls, normal_calls
        if "rule.mitre.id" in payload["query"]:
            technique_calls += 1
            return {"record_count": 1, "logs": [{"event": "technique event"}]}
        normal_calls += 1
        return {"record_count": 0, "logs": []}

    monkeypatch.setattr(siem_fetch, "call_tool", fake_call_tool)
    state = {
        "siem_type": "wazuh",
        "hypothesis_text": "Network service discovery",
        "query": '{"query":{"match_all":{}}}',
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "executed_queries": [],
    }
    first = asyncio.run(siem_fetch.fetch_logs_node(state))
    second = asyncio.run(siem_fetch.fetch_logs_node(state))

    assert technique_calls == 1
    assert normal_calls == 2
    assert first["telemetry_cache_hit"] is False
    assert second["telemetry_cache_hit"] is True
    assert second["technique_telemetry_records"] == 1
