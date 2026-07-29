import asyncio
import json
from unittest.mock import AsyncMock

from services import chat_agent
from services.communication.audience import communicate_node
from services.coverage.gap_analysis import coverage_gap_node
from services.enrichment.threat_intel import enrich_iocs_node
from services.enrichment import ioc_management
from services.hunting import hypothesis, kb_refresh
from services.memory import hunt_memory
from services.memory.chat_memory import _clean_message
from services.siem.log_processing import process_logs_node


def test_ask_thos_receives_citable_product_context(monkeypatch):
    prompts = []

    async def fake_plan(prompt):
        prompts.append(prompt)
        return {
            "answer": "Use contract, behavior, and live acceptance layers.",
            "tool_calls": [],
        }

    monkeypatch.setattr(chat_agent, "_generate_plan", fake_plan)
    result = asyncio.run(chat_agent.chat(
        "How do I test every THOS agent?", [], "analyst-a",
    ))

    assert "[PK-TESTING]" in prompts[0]
    assert any(source["id"] == "PK-TESTING" for source in result["knowledge_sources"])
    assert "[PK-TESTING]" in result["answer"]
    assert result["tools_used"] == []


def test_chat_memory_preserves_bounded_product_source_metadata():
    result = _clean_message({
        "role": "assistant",
        "content": "Supported SIEMs are listed in the product catalog.",
        "sources": [{
            "id": "PK-SOURCES",
            "title": "Supported telemetry and SIEM sources",
            "source": "README.md",
            "ignored": "must not persist",
        }],
    })

    assert result["sources"] == [{
        "id": "PK-SOURCES",
        "title": "Supported telemetry and SIEM sources",
        "source": "README.md",
    }]


def test_chat_memory_preserves_specialist_agent_metadata():
    result = _clean_message({
        "role": "assistant",
        "content": "The forensic specialist reviewed the timeline.",
        "agents": [{
            "agent_id": "forensic_investigation_specialist",
            "agent_name": "Digital Forensic Specialist Agent",
            "model_tier": "reasoning",
            "model_name": "qwen3:4b",
            "duration_ms": 1234,
            "ignored": "must not persist",
        }],
    })

    assert result["agents"] == [{
        "agent_id": "forensic_investigation_specialist",
        "agent_name": "Digital Forensic Specialist Agent",
        "model_tier": "reasoning",
        "model_name": "qwen3:4b",
        "duration_ms": 1234,
    }]


def test_ask_thos_delegates_authorized_investigation_question(monkeypatch):
    plans = iter([
        {
            "answer": "",
            "tool_calls": [{
                "name": "delegate_hunt_specialist",
                "arguments": {"hunt_id": "hunt-123", "focus": "Explain the strongest finding"},
            }],
        },
        {"answer": "The specialist found a cited suspicious process.", "tool_calls": []},
    ])

    async def fake_plan(_prompt):
        return next(plans)

    async def fake_investigation_tool(name, arguments):
        assert name == "delegate_hunt_specialist"
        assert arguments["hunt_id"] == "hunt-123"
        return {
            "delegated_agent": {
                "agent_id": "hunt_investigation_specialist",
                "agent_name": "Hunt Investigation Specialist Agent",
                "model_tier": "reasoning",
                "model_name": "qwen3:4b",
                "duration_ms": 42,
            },
            "assessment": {"findings": ["record-7"]},
        }

    monkeypatch.setattr(chat_agent, "_generate_plan", fake_plan)
    monkeypatch.setattr(chat_agent, "_call_investigation_tool", fake_investigation_tool)
    result = asyncio.run(chat_agent.chat(
        "Investigate hunt ID hunt-123", [], "analyst-a",
        role="Expert", permissions=["chat", "hunts"],
    ))

    assert result["tools_used"] == ["delegate_hunt_specialist"]
    assert result["delegated_agents"][0]["agent_name"] == "Hunt Investigation Specialist Agent"


def test_ask_thos_filters_investigation_tools_without_feature_grant(monkeypatch):
    async def fake_plan(_prompt):
        return {
            "answer": "I cannot read forensic state with the current authorization.",
            "tool_calls": [{"name": "read_forensic_investigation", "arguments": {}}],
        }

    monkeypatch.setattr(chat_agent, "_generate_plan", fake_plan)
    result = asyncio.run(chat_agent.chat(
        "Read the latest forensic investigation", [], "analyst-a",
        role="Expert", permissions=["chat"],
    ))

    assert result["tools_used"] == []
    assert result["delegated_agents"] == []


def test_ask_thos_forces_cyber_retrieval_and_withholds_uncited_answer(monkeypatch):
    plans = iter([
        {"answer": "Credential dumping extracts credentials.", "tool_calls": []},
        {"answer": "Credential dumping extracts credentials.", "tool_calls": []},
    ])

    async def fake_plan(_prompt):
        return next(plans)

    async def fake_call_tool(name, _arguments):
        assert name == "search_cyber_knowledge"
        return [{
            "citation_id": "CYBER:mitre_attack_enterprise:T1003:0",
            "text": "Credential dumping may extract credential material.",
            "source": {"id": "mitre_attack_enterprise"},
        }]

    monkeypatch.setattr(chat_agent, "_generate_plan", fake_plan)
    monkeypatch.setattr(chat_agent, "call_tool", fake_call_tool)
    result = asyncio.run(chat_agent.chat(
        "Explain MITRE T1003 credential dumping.", [], "analyst-a",
    ))

    assert "claims were withheld" in result["answer"]
    assert "[CYBER:mitre_attack_enterprise:T1003:0]" in result["answer"]
    assert result["tools_used"] == ["search_cyber_knowledge"]


def test_general_detection_question_uses_cyber_corpus_even_if_product_catalog_matches(monkeypatch):
    plans = iter([
        {"answer": "Initial answer.", "tool_calls": []},
        {
            "answer": (
                "Detection engineering should connect observable behavior to "
                "tested analytics [CYBER:mitre_attack_enterprise:T1059.001:0]."
            ),
            "tool_calls": [],
        },
    ])

    async def fake_plan(_prompt):
        return next(plans)

    async def fake_call_tool(name, _arguments):
        assert name == "search_cyber_knowledge"
        return [{
            "citation_id": "CYBER:mitre_attack_enterprise:T1059.001:0",
            "text": "PowerShell is an ATT&CK sub-technique.",
            "source": {"id": "mitre_attack_enterprise"},
        }]

    monkeypatch.setattr(chat_agent, "_generate_plan", fake_plan)
    monkeypatch.setattr(chat_agent, "call_tool", fake_call_tool)
    result = asyncio.run(chat_agent.chat(
        "How should threat detection engineering cover PowerShell?", [], "analyst-a",
    ))

    assert result["tools_used"] == ["search_cyber_knowledge"]
    assert "[CYBER:mitre_attack_enterprise:T1059.001:0]" in result["answer"]


def test_hypothesis_agent_uses_local_mitre_mapping(monkeypatch):
    calls = []

    async def fake_call_tool(name, arguments):
        calls.append((name, arguments))
        return {"name": "PowerShell", "tactic": "Execution"}

    monkeypatch.setattr(hypothesis, "call_tool", fake_call_tool)
    result = asyncio.run(hypothesis.select_hypothesis({
        "hypothesis_id": "H-001",
        "hypothesis_text": "Suspicious PowerShell",
        "hypothesis_tactic": "Execution",
        "hypothesis_technique": "T1059.001",
    }))

    assert result["technique_id"] == "T1059.001"
    assert result["technique_name"] == "PowerShell"
    assert calls == [("mitre_map_technique", {"technique_id": "T1059.001"})]


def test_hearth_refresh_agent_respects_fresh_cache(monkeypatch):
    monkeypatch.setenv("HEARTH_REFRESH_DURING_HUNT", "1")
    call_tool = AsyncMock(return_value={"hit": True})
    monkeypatch.setattr(kb_refresh, "call_tool", call_tool)

    assert asyncio.run(kb_refresh.refresh_hearth_kb_node({})) == {}
    call_tool.assert_awaited_once_with(
        "cache_lookup",
        {"namespace": "hearth_kb_refresh", "payload": "last_refresh"},
    )


def test_hearth_refresh_agent_is_outside_hunt_path_by_default(monkeypatch):
    monkeypatch.delenv("HEARTH_REFRESH_DURING_HUNT", raising=False)
    call_tool = AsyncMock()
    monkeypatch.setattr(kb_refresh, "call_tool", call_tool)

    assert asyncio.run(kb_refresh.refresh_hearth_kb_node({})) == {}
    call_tool.assert_not_awaited()


def test_hunt_memory_is_technique_scoped(monkeypatch):
    recent = AsyncMock(return_value=[{"hunt_id": "hunt-old"}])
    monkeypatch.setattr(hunt_memory.audit, "recent_hunt_memory", recent)

    result = asyncio.run(hunt_memory.recall_hunt_memory_node({"technique_id": "T1059.001"}))

    assert result["hunt_memory"][0]["hunt_id"] == "hunt-old"
    recent.assert_awaited_once_with("T1059.001")


def test_log_processing_deduplicates_stable_event_identity():
    duplicate = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "host-1",
        "user": "alice",
        "event": "4688",
        "detail": "powershell.exe",
    }

    result = asyncio.run(process_logs_node({"logs": [duplicate, dict(duplicate)]}))

    assert len(result["processed_logs"]) == 1
    assert all(result["processed_logs"][0][key] == value for key, value in duplicate.items())
    assert result["processed_logs"][0]["source_product"] == "Windows Security"
    assert result["processed_logs"][0]["device_type"] == "endpoint"
    assert result["processed_logs"][0]["event_category"] == "process"


def test_coverage_agent_does_not_use_record_count_heuristics(monkeypatch):
    from services.coverage import gap_analysis

    monkeypatch.setattr(gap_analysis.mitre, "map_technique", lambda _value: {
        "name": "Test",
        "data_sources": ["Process Creation"],
    })

    async def decision(**kwargs):
        return kwargs["validator"]({
            "overall_status": "covered",
            "data_sources": [{
                "data_source": "Process Creation",
                "status": "covered",
                "confidence": "high",
                "reason": "The supplied record is a process event.",
                "evidence_refs": ["record:0"],
                "missing_requirements": [],
            }],
            "gaps": [],
        })

    monkeypatch.setattr(gap_analysis, "decide_json", decision)
    result = asyncio.run(coverage_gap_node({
        "technique_id": "T0000",
        "processed_logs": [{"event": "process"}],
        "source_diagnostics": {"folder": {"status": "queried"}},
        "siem_types": ["folder"],
    }))

    assert result["coverage_assessment"]["status"] == "covered"
    assert result["coverage_gaps"] == []


def test_threat_intel_agent_uses_only_local_blocklist(tmp_path, monkeypatch):
    blocklist = tmp_path / "blocklist.json"
    blocklist.write_text(json.dumps({
        "indicators": {"8.8.8.8": {"confidence": "high"}},
    }), encoding="utf-8")
    monkeypatch.setenv("THOS_IOC_BLOCKLIST_PATH", str(blocklist))

    result = asyncio.run(enrich_iocs_node({
        "processed_logs": [{"detail": "connection to 8.8.8.8"}],
    }))

    assert result["enrichment_hits"] == [{
        "indicator": "8.8.8.8",
        "record_index": 0,
        "source": "local_blocklist",
        "metadata": {"confidence": "high"},
    }]


def test_threat_intel_suppresses_private_range_false_positive(monkeypatch):
    monkeypatch.delenv("THOS_IOC_MATCH_PRIVATE", raising=False)
    monkeypatch.setattr(ioc_management, "load_blocklist", lambda: {
        "indicators": {
            "172.16.0.0/12": {
                "type": "network",
                "confidence": "low",
                "source": "public-feed",
            },
        },
    })

    result = asyncio.run(enrich_iocs_node({
        "processed_logs": [{"src_ip": "172.20.0.4", "detail": "internal traffic"}],
    }))

    assert result["enrichment_hits"] == []


def test_communication_agent_changes_audience_not_evidence():
    state = {"reasoning_summary": "Two cited records support the hypothesis."}
    executive = asyncio.run(communicate_node({**state, "cover_style": "1"}))
    analyst = asyncio.run(communicate_node({**state, "cover_style": "2"}))
    compliance = asyncio.run(communicate_node({**state, "cover_style": "3"}))

    assert "Two cited records" in executive["communication_summary"]
    assert "Two cited records" in analyst["communication_summary"]
    assert "Two cited records" in compliance["communication_summary"]
    assert executive != analyst != compliance
