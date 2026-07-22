"""
Unit tests for services.mcp.soc_tools.run_soc_tools_node.

The Sigma engines and the MCP tool call are monkeypatched so these tests
exercise only the merge/tagging logic in soc_tools.py itself — not
pySigma rule parsing (covered in tests/detection/test_sigmahq_engine.py)
or the real MCP round trip.
"""
import asyncio
import threading

import pytest

from services.mcp import soc_tools


def _hq_result(matches, evaluated=2843):
    matched = sorted({i for rm in matches for i in rm["matched_indices"]})
    return {"matched_record_indices": matched, "rule_matches": matches, "rules_evaluated": evaluated}


def _thos_result(matches, evaluated=16):
    matched = sorted({i for rm in matches for i in rm["matched_indices"]})
    return {"matched_record_indices": matched, "rule_matches": matches, "rules_evaluated": evaluated}


def test_merges_all_three_layers_and_tags_records(monkeypatch):
    processed_logs = [{"detail": f"record {i}"} for i in range(4)]

    hq_matches = [{"rule_id": "hq-1", "title": "HQ Rule", "level": "high",
                   "matched_indices": [0], "matched_count": 1}]
    thos_matches = [{"rule_id": "thos-1", "title": "THOS Rule", "level": "medium",
                      "matched_indices": [1], "matched_count": 1}]

    monkeypatch.setattr(soc_tools.sigmahq_engine, "evaluate_all",
                         lambda *a, **k: _hq_result(hq_matches))
    monkeypatch.setattr(soc_tools.sigma_engine, "evaluate_all",
                         lambda *a, **k: _thos_result(thos_matches))

    async def fake_call_tool(name, args):
        assert name == "derive_detection_indicators"
        return {"event_ids": [], "keywords": ["mimikatz"]}
    monkeypatch.setattr(soc_tools, "call_tool", fake_call_tool)

    processed_logs[2]["detail"] = "record 2 mentions mimikatz"

    state = {
        "processed_logs": processed_logs,
        "hypothesis_text": "test hypothesis",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "credential-access",
    }

    result = asyncio.run(soc_tools.run_soc_tools_node(state))

    # All three layers' hits are unioned.
    assert result["sigma_matched_refs"] == [0, 1, 2]
    assert result["sigma_matched_count"] == 3

    # Per-record tags reflect exactly which layer(s) hit.
    assert processed_logs[0]["_sigma_match"] is True
    assert processed_logs[0]["_sigmahq_match"] is True
    assert processed_logs[0]["_llm_indicator_match"] is False
    assert processed_logs[1]["_sigmahq_match"] is False
    assert processed_logs[2]["_llm_indicator_match"] is True
    assert processed_logs[3].get("_sigma_match") is None

    # Rule match summary carries a source tag per rule.
    sources = {rm["rule_id"]: rm["source"] for rm in result["sigma_rule_matches"]}
    assert sources == {"hq-1": "sigmahq", "thos-1": "thos"}

    enrichment = result["enrichment"]
    assert enrichment["sigmahq_rules_evaluated"] == 2843
    assert enrichment["thos_rules_evaluated"] == 16
    assert enrichment["sigma_rules_evaluated"] == 2843 + 16
    assert enrichment["llm_indicator_matched_records"] == 1


def test_empty_sigmahq_ruleset_still_works(monkeypatch):
    processed_logs = [{"detail": "record 0"}]

    monkeypatch.setattr(soc_tools.sigmahq_engine, "evaluate_all",
                         lambda *a, **k: _hq_result([], evaluated=0))
    monkeypatch.setattr(soc_tools.sigma_engine, "evaluate_all",
                         lambda *a, **k: _thos_result([], evaluated=16))

    async def fake_call_tool(name, args):
        return {"event_ids": [], "keywords": []}
    monkeypatch.setattr(soc_tools, "call_tool", fake_call_tool)

    state = {"processed_logs": processed_logs, "hypothesis_text": "", "technique_id": "",
             "technique_name": "", "tactic": ""}

    result = asyncio.run(soc_tools.run_soc_tools_node(state))

    assert result["sigma_matched_count"] == 0
    assert "16 applicable rule" in result["sigma_rule"]


def test_live_siem_uses_query_pushdown_not_local_evaluation(monkeypatch):
    async def pushed(**kwargs):
        assert kwargs["siem_type"] == "splunk"
        return {
            "processed_logs": [{
                "timestamp": "2026-07-22T00:00:00Z", "host": "srv-1",
                "event": "4688", "detail": "encoded powershell",
                "_sigma_match": True, "_sigmahq_match": True,
                "_sigma_rules": ["[sigmahq] hq-1:Encoded PowerShell"],
            }],
            "rule_matches": [{
                "rule_id": "hq-1", "title": "Encoded PowerShell", "level": "high",
                "source": "sigmahq", "matched_count": 1, "matched_indices": [0],
            }],
            "rules_evaluated": 1,
            "coverage": {"relevant": 1, "ready": 1, "unsupported": 0, "truncated": 0},
            "errors": [],
        }

    monkeypatch.setattr(soc_tools, "query_sigma_for_hunt", pushed)
    monkeypatch.setattr(
        soc_tools.sigmahq_engine, "evaluate_all",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local evaluator must not run")),
    )
    monkeypatch.setattr(
        soc_tools.sigma_engine, "evaluate_all",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("local evaluator must not run")),
    )

    async def fake_call_tool(name, args):
        return {"event_ids": [], "keywords": []}

    monkeypatch.setattr(soc_tools, "call_tool", fake_call_tool)
    result = asyncio.run(soc_tools.run_soc_tools_node({
        "siem_type": "splunk", "processed_logs": [], "technique_id": "T1059.001",
        "hypothesis_text": "encoded PowerShell",
    }))
    assert result["enrichment"]["sigma_execution_mode"] == "siem_query_pushdown"
    assert result["sigma_matched_count"] == 1
    assert result["processed_logs"][0]["_sigma_match"] is True


def test_sigma_and_indicator_work_start_concurrently(monkeypatch):
    sigma_started = threading.Event()
    indicator_started = threading.Event()

    def sigma_eval(*args, **kwargs):
        sigma_started.set()
        assert indicator_started.wait(timeout=2), "indicator call was awaited after Sigma"
        return _hq_result([], evaluated=1)

    monkeypatch.setattr(soc_tools.sigmahq_engine, "evaluate_all", sigma_eval)
    monkeypatch.setattr(
        soc_tools.sigma_engine, "evaluate_all",
        lambda *args, **kwargs: _thos_result([], evaluated=1),
    )

    async def indicator_call(name, args):
        indicator_started.set()
        for _ in range(200):
            if sigma_started.is_set():
                break
            await asyncio.sleep(0.01)
        assert sigma_started.is_set(), "Sigma work was awaited after indicator derivation"
        return {"event_ids": [], "keywords": []}

    monkeypatch.setattr(soc_tools, "call_tool", indicator_call)
    result = asyncio.run(soc_tools.run_soc_tools_node({"processed_logs": []}))

    assert result["enrichment"]["sigma_rules_evaluated"] == 2
