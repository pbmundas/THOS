import asyncio
import json

from services.detection import detection_analysis_agent as agent


def _detection():
    return {
        "run_id": "11111111-1111-1111-1111-111111111111",
        "detection_uid": "DET-11111111-1111-1111-1111-111111111111",
        "rule_id": "rule-1",
        "rule_title": "Reconnaissance tool observed",
        "level": "high",
        "events_matched": 1,
        "matched_events": [{
            "record_ref": "wazuh:1",
            "timestamp": "2026-07-28T10:00:00Z",
            "host": "server-1",
            "event": "process_creation",
            "detail": "nmap -sV target",
        }],
        "analysis": {"summary": "One event matched."},
    }


def test_detection_analysis_uses_one_fast_tier_model_call(monkeypatch):
    calls = []

    async def fake_generate(*args, **kwargs):
        calls.append((args, kwargs))
        return json.dumps({
            "analysis_lines": [f"Evidence line {number}." for number in range(1, 6)],
            "confidence": "medium",
            "evidence_refs": ["wazuh:1"],
        })

    monkeypatch.setattr(agent, "generate", fake_generate)
    result = asyncio.run(agent.analyze_detection(_detection()))

    assert len(calls) == 1
    assert calls[0][1]["agent"] == "detection_analysis"
    assert calls[0][1]["transport_retries"] == 0
    assert len(result["analysis_lines"]) == 5
    assert result["generation_mode"] == "local_model"
    assert result["detection_uid"].startswith("DET-")


def test_detection_analysis_falls_back_to_seven_evidence_bounded_lines(monkeypatch):
    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("model busy")

    monkeypatch.setattr(agent, "generate", unavailable)
    result = asyncio.run(agent.analyze_detection(_detection()))

    assert len(result["analysis_lines"]) == 7
    assert result["generation_mode"] == "deterministic_fallback"
    assert result["confidence"] == "medium"
    assert result["evidence_refs"] == ["wazuh:1"]
