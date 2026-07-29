import asyncio
import json

from services.orchestration import supervisor
from services.siem import siem_fetch


def test_supervisor_agent_owns_refinement_and_query_agent_builds_syntax(
    monkeypatch,
):
    async def decision(**kwargs):
        return kwargs["validator"]({
            "action": "refine_query",
            "objective": "Retrieve network-service discovery events.",
            "source": "wazuh",
            "lookback_minutes": 240,
            "limit": 50,
            "reason": "The first evidence branch is not resolved.",
        })

    async def query_agent(_name, payload):
        assert payload["objective"].startswith("Retrieve network-service")
        return {
            "query": json.dumps({
                "query": {"term": {"rule.mitre.id": "T1046"}},
            }),
        }

    monkeypatch.setattr(supervisor, "decide_json", decision)
    monkeypatch.setattr(supervisor, "call_tool", query_agent)
    result = asyncio.run(supervisor.adaptive_replan_node({
        "adaptive_replans": 0,
        "max_adaptive_replans": 4,
        "siem_type": "wazuh",
        "siem_types": ["wazuh"],
        "source_diagnostics": {"wazuh": {"status": "queried"}},
        "hypothesis_text": "Investigate network service discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "retrieval_attempts": [],
        "max_lookback_minutes": 10080,
        "max_query_limit": 2000,
    }))

    assert result["replan_action"] == "refine_query"
    assert result["follow_up_source"] == "wazuh"
    assert result["follow_up_lookback_minutes"] == 240
    assert "T1046" in result["follow_up_query"]
    assert result["replan_decision_owner"] == "supervisor_model"


def test_same_query_with_larger_window_is_not_a_duplicate(monkeypatch):
    calls = []

    async def fake_call_tool(_name, payload):
        calls.append(payload)
        return {"record_count": 0, "total_hits": 0, "logs": []}

    monkeypatch.setattr(siem_fetch, "call_tool", fake_call_tool)
    base = {
        "siem_type": "splunk",
        "active_query_source": "splunk",
        "hypothesis_text": "PowerShell",
        "query": "powershell",
        "executed_queries": [],
        "executed_query_keys": [],
        "retrieval_attempts": [],
        "active_query_limit": 25,
        "active_lookback_minutes": 60,
    }
    first = asyncio.run(siem_fetch.fetch_logs_node(base))
    second = asyncio.run(siem_fetch.fetch_logs_node({
        **base,
        **first,
        "follow_up_query": "powershell",
        "follow_up_source": "splunk",
        "follow_up_lookback_minutes": 240,
    }))

    assert len(calls) == 2
    assert calls[0]["lookback_minutes"] == 60
    assert calls[1]["lookback_minutes"] == 240
    assert len(second["retrieval_attempts"]) == 2


def test_source_failure_is_recorded_without_failing_multi_source_graph(
    monkeypatch,
):
    async def fake_call_tool(_name, _payload):
        return {
            "record_count": 0,
            "total_hits": 0,
            "logs": [],
            "error": "connector unavailable",
        }

    monkeypatch.setattr(siem_fetch, "call_tool", fake_call_tool)
    result = asyncio.run(siem_fetch.fetch_logs_node({
        "siem_type": "splunk",
        "siem_types": ["splunk", "wazuh"],
        "active_query_source": "splunk",
        "hypothesis_text": "Network service discovery",
        "query": "index=* nmap",
        "executed_queries": [],
        "executed_query_keys": [],
        "retrieval_attempts": [],
    }))

    assert result["error"] is None
    assert result["source_diagnostics"]["splunk"]["status"] == "unavailable"
    assert result["retrieval_attempts"][0]["error"] == "connector unavailable"


def test_observed_entity_pivots_are_literal_and_bounded():
    records = [
        {
            "host": f"server-{index}",
            "user": "analyst",
            "src_ip": f"10.0.0.{index}",
            "event": "process",
        }
        for index in range(30)
    ]

    observed = supervisor._observed_entities({"processed_logs": records})

    assert observed["hosts"][0] == "server-0"
    assert observed["users"] == ["analyst"]
    assert len(observed["hosts"]) == 20
    assert len(observed["source_ips"]) == 20
