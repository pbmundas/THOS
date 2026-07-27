import pytest

from services.detection import sigma_detection_agent


@pytest.mark.asyncio
async def test_hunt_sigma_uses_one_wazuh_msearch(monkeypatch):
    entries = [
        {
            "rule_id": "r1", "title": "Rule one", "level": "high",
            "rule_source": "SigmaHQ", "query": '{"query":{"match_all":{}}}',
        },
        {
            "rule_id": "r2", "title": "Rule two", "level": "medium",
            "rule_source": "THOS", "query": '{"query":{"match_all":{}}}',
        },
    ]
    calls = []

    monkeypatch.setattr(
        sigma_detection_agent,
        "applicable_rules",
        lambda *_args: (entries, {"unsupported": 0, "truncated": 0}),
    )

    def fake_multi(requests, limit):
        calls.append((requests, limit))
        return [
            {"logs": [{"event": "match", "detail": "one"}]},
            {"logs": []},
        ]

    monkeypatch.setattr(
        sigma_detection_agent.wazuh_connector, "fetch_multi_logs", fake_multi
    )
    result = await sigma_detection_agent.query_sigma_for_hunt(
        siem_type="wazuh", technique_id="T1046"
    )

    assert len(calls) == 1
    assert len(calls[0][0]) == 2
    assert result["coverage"]["execution_mode"] == "wazuh_msearch"
    assert result["rules_evaluated"] == 2
    assert len(result["rule_matches"]) == 1


@pytest.mark.asyncio
async def test_scheduled_rule_batch_uses_one_wazuh_msearch(monkeypatch):
    entries = {
        "r1": {
            "rule_id": "r1", "title": "Rule one", "level": "high",
            "rule_source": "SigmaHQ", "query": '{"query":{"match_all":{}}}',
            "tags": [],
        },
        "r2": {
            "rule_id": "r2", "title": "Rule two", "level": "medium",
            "rule_source": "THOS", "query": '{"query":{"match_all":{}}}',
            "tags": [],
        },
    }
    calls = []
    monkeypatch.setattr(
        sigma_detection_agent,
        "find_rule",
        lambda rule_id, _siem: entries[rule_id],
    )

    def fake_multi(requests, limit):
        calls.append((requests, limit))
        return [
            {"logs": [{"event": "match", "detail": "one"}]},
            {"logs": []},
        ]

    monkeypatch.setattr(
        sigma_detection_agent.wazuh_connector, "fetch_multi_logs", fake_multi
    )
    monkeypatch.setattr(
        sigma_detection_agent,
        "deduplicate_recurring_hits",
        lambda _rule, _siem, events, **_kwargs: (
            events,
            {
                "raw_events_matched": len(events),
                "new_events_matched": len(events),
                "duplicates_suppressed": 0,
            },
        ),
    )

    results = await sigma_detection_agent.run_scheduled_sigma_batch(
        schedule_id="schedule", rule_ids=["r1", "r2"], siem_type="wazuh"
    )

    assert len(calls) == 1
    assert len(calls[0][0]) == 2
    assert [result["status"] for result in results] == ["detected", "no_match"]
    assert all(
        result["analysis"]["method"] == "single Wazuh scheduled multi-search batch"
        for result in results
    )


@pytest.mark.asyncio
async def test_scheduled_rule_batch_halves_on_siem_transport_pressure(monkeypatch):
    entries = {
        rule_id: {
            "rule_id": rule_id,
            "title": rule_id,
            "level": "medium",
            "rule_source": "Community",
            "query": '{"query":{"match_all":{}}}',
            "tags": [],
        }
        for rule_id in ("r1", "r2")
    }
    calls = []
    monkeypatch.setattr(
        sigma_detection_agent,
        "find_rule",
        lambda rule_id, _siem: entries[rule_id],
    )

    def pressure_sensitive_multi(requests, _limit):
        calls.append(len(requests))
        if len(requests) > 1:
            raise ConnectionError("backend closed overloaded request")
        return [{"logs": []}]

    monkeypatch.setattr(
        sigma_detection_agent.wazuh_connector,
        "fetch_multi_logs",
        pressure_sensitive_multi,
    )
    results = await sigma_detection_agent.run_scheduled_sigma_batch(
        schedule_id="schedule", rule_ids=["r1", "r2"], siem_type="wazuh"
    )

    assert calls == [2, 1, 1]
    assert [result["status"] for result in results] == ["no_match", "no_match"]
    assert all(
        result["analysis"]["multi_search_requests"] == 3
        for result in results
    )
