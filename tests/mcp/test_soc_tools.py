"""Tests for detection correlation plus agent-owned evidence selection."""
import asyncio

from services.mcp import soc_tools


def _result(matches, evaluated):
    matched = sorted({
        index
        for match in matches
        for index in match["matched_indices"]
    })
    return {
        "matched_record_indices": matched,
        "rule_matches": matches,
        "rules_evaluated": evaluated,
    }


def test_rule_facts_and_agent_selected_evidence_are_kept_separate(monkeypatch):
    records = [
        {"event": "rule matched", "detail": "record zero"},
        {"event": "process", "detail": "literal governed-tool.exe"},
    ]
    community = [{
        "rule_id": "community-1",
        "title": "Community rule",
        "level": "high",
        "matched_indices": [0],
        "matched_count": 1,
    }]
    monkeypatch.setattr(
        soc_tools.sigmahq_engine,
        "evaluate_all",
        lambda *args, **kwargs: _result(community, 10),
    )
    monkeypatch.setattr(
        soc_tools.sigma_engine,
        "evaluate_all",
        lambda *args, **kwargs: _result([], 2),
    )

    async def indicators(_name, _arguments):
        return {"keywords": ["governed-tool.exe"]}

    async def selection(**_kwargs):
        return {
            "assessment": "One literal artifact supports review.",
            "evidence": [{
                "record_index": 1,
                "kind": "artifact",
                "claim": "The governed executable name is present.",
                "matched_literals": ["governed-tool.exe"],
                "event": "process",
                "evidence": "literal governed-tool.exe",
            }],
        }

    monkeypatch.setattr(soc_tools, "call_tool", indicators)
    monkeypatch.setattr(soc_tools, "select_hunt_evidence", selection)
    result = asyncio.run(soc_tools.run_soc_tools_node({
        "siem_type": "folder",
        "processed_logs": records,
        "hypothesis_text": "Investigate governed-tool.exe",
        "technique_id": "T1003",
        "technique_name": "Credential Access",
        "tactic": "credential-access",
        "active_query_objective": "Find related execution evidence",
    }))

    assert result["sigma_matched_refs"] == [0]
    assert result["sigma_matched_count"] == 1
    assert records[0]["_sigma_match"] is True
    assert records[1]["_llm_indicator_match"] is True
    assert result["evidence_highlights"][0]["record_index"] == 1
    assert result["enrichment"]["llm_indicator_matched_records"] == 1


def test_empty_agent_selection_does_not_fabricate_evidence(monkeypatch):
    monkeypatch.setattr(
        soc_tools.sigmahq_engine,
        "evaluate_all",
        lambda *args, **kwargs: _result([], 0),
    )
    monkeypatch.setattr(
        soc_tools.sigma_engine,
        "evaluate_all",
        lambda *args, **kwargs: _result([], 2),
    )

    async def indicators(_name, _arguments):
        return {}

    async def selection(**_kwargs):
        return {"assessment": "No relevant evidence.", "evidence": []}

    monkeypatch.setattr(soc_tools, "call_tool", indicators)
    monkeypatch.setattr(soc_tools, "select_hunt_evidence", selection)
    result = asyncio.run(soc_tools.run_soc_tools_node({
        "siem_type": "folder",
        "processed_logs": [{"event": "unrelated", "detail": "routine"}],
    }))

    assert result["sigma_matched_count"] == 0
    assert result["behavioral_evidence"] == []
    assert result["evidence_highlights"] == []


def test_live_source_uses_query_pushdown(monkeypatch):
    async def pushed(**kwargs):
        assert kwargs["siem_type"] == "splunk"
        return {
            "processed_logs": [{
                "timestamp": "2026-07-22T00:00:00Z",
                "event": "process",
                "detail": "literal event",
                "_sigma_match": True,
            }],
            "rule_matches": [{
                "rule_id": "rule-1",
                "title": "Rule",
                "level": "high",
                "source": "community",
                "matched_count": 1,
                "matched_indices": [0],
            }],
            "rules_evaluated": 1,
            "coverage": {
                "relevant": 1,
                "ready": 1,
                "unsupported": 0,
                "truncated": 0,
            },
            "errors": [],
        }

    async def indicators(_name, _arguments):
        return {}

    async def selection(**_kwargs):
        return {"assessment": "", "evidence": []}

    monkeypatch.setattr(soc_tools, "query_sigma_for_hunt", pushed)
    monkeypatch.setattr(soc_tools, "call_tool", indicators)
    monkeypatch.setattr(soc_tools, "select_hunt_evidence", selection)
    result = asyncio.run(soc_tools.run_soc_tools_node({
        "siem_type": "splunk",
        "processed_logs": [],
        "technique_id": "T1059.001",
        "hypothesis_text": "encoded PowerShell",
    }))

    assert result["enrichment"]["sigma_execution_mode"] == (
        "siem_query_pushdown"
    )
    assert result["sigma_matched_count"] == 1
