import asyncio
import json

import pytest

from services.hunting import evidence_selector
from services.reasoning.reasoning import _slim_log


def test_nmap_evidence_is_selected_by_agent_and_literal_validated(monkeypatch):
    record = {
        "event": "Web server 400 error code.",
        "detail": "x" * 2_000,
        "evidence_summary": (
            "URL: /nmaplowercheck; full log: Mozilla/5.0 "
            "(compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        ),
    }

    async def fake_decide_json(**kwargs):
        return kwargs["validator"]({
            "assessment": "The record contains a literal scanner artifact.",
            "evidence": [{
                "record_index": 0,
                "kind": "artifact",
                "claim": "Nmap scripting-engine text is present.",
                "matched_literals": ["Nmap Scripting Engine"],
            }],
        })

    monkeypatch.setattr(evidence_selector, "decide_json", fake_decide_json)
    result = asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[record],
        hypothesis_text="Investigate network service discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="discovery",
        objective="Find service discovery evidence",
        indicators={},
        detection_rule_refs=[],
    ))
    slim = _slim_log(record, ref=0)

    assert "Nmap Scripting Engine" in slim["evidence_summary"]
    assert slim["detail"].endswith("(truncated)")
    assert result["evidence"][0]["record_index"] == 0
    assert result["evidence"][0]["matched_literals"] == [
        "Nmap Scripting Engine"
    ]


def test_empty_telemetry_skips_evidence_model(monkeypatch):
    async def model_must_not_run(**_kwargs):
        raise AssertionError("model should not run without records")

    monkeypatch.setattr(
        evidence_selector,
        "decide_json",
        model_must_not_run,
    )
    result = asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[],
        hypothesis_text="Investigate network service discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        objective="Retrieve scanner evidence",
        indicators={},
        detection_rule_refs=[],
    ))

    assert result["evidence"] == []
    assert result["_decision_metadata"]["owner"] == (
        "deterministic_empty_input"
    )


def test_model_prompt_compacts_duplicate_raw_telemetry(monkeypatch):
    record = {
        "timestamp": "2026-07-30T00:00:00Z",
        "event": "Network connection",
        "detail": "duplicated-detail-" * 1_000,
        "full_log": "duplicated-full-log-" * 1_000,
        "evidence_summary": "destination port: 3389 | TCP SYN: true",
        "_raw": {"payload": "raw-payload-" * 2_000},
        "dst_port": "3389",
    }
    captured = {}

    async def fake_decide_json(**kwargs):
        captured.update(kwargs)
        return kwargs["validator"]({
            "assessment": "The normalized summary is sufficient.",
            "evidence": [{
                "record_index": 0,
                "kind": "behavioral",
                "claim": "A SYN connection targeted the governed port.",
                "matched_literals": ["3389"],
            }],
        })

    monkeypatch.setattr(evidence_selector, "decide_json", fake_decide_json)
    result = asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[record],
        hypothesis_text=(
            "Investigate TCP SYN network service discovery on port 3389"
        ),
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        objective="Retrieve scanner evidence",
        indicators={},
        detection_rule_refs=[],
    ))

    prompt = json.loads(captured["prompt"])
    model_record = prompt["records"][0]["record"]
    assert model_record["evidence_summary"] == record["evidence_summary"]
    assert model_record["dst_port"] == "3389"
    assert "detail" not in model_record
    assert "full_log" not in model_record
    assert "_raw" not in model_record
    assert captured["schema"]["properties"]["evidence"]["maxItems"] == 3
    assert captured["schema"]["properties"]["evidence"]["minItems"] == 1
    assert prompt["grounded_candidate_refs"] == [0]
    assert captured["attempts"] == 1
    assert captured["num_predict"] == 384
    assert captured["timeout_seconds"] == 120
    assert captured["transport_retries"] == 0
    assert result["evidence"][0]["record_index"] == 0


def test_grounded_literal_fallback_retains_verified_evidence(monkeypatch):
    record = {
        "event": "Network connection",
        "evidence_summary": "TCP SYN to destination port 3389",
    }

    async def failed_decision(**_kwargs):
        raise evidence_selector.AgentDecisionError("model timeout")

    monkeypatch.setattr(evidence_selector, "decide_json", failed_decision)
    result = asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[record],
        hypothesis_text="Investigate TCP SYN discovery of port 3389",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        objective="Retrieve scanner evidence",
        indicators={},
        detection_rule_refs=[],
    ))

    assert result["_decision_metadata"]["owner"] == (
        "deterministic_grounded_fallback"
    )
    assert result["evidence"][0]["record_index"] == 0
    assert len(result["evidence"][0]["matched_literals"]) >= 2


def test_grounded_literal_matching_rejects_numeric_substrings(monkeypatch):
    record = {
        "event": "Network connection",
        "evidence_summary": "TCP SYN to destination port 3389",
    }
    captured = {}

    async def fake_decide_json(**kwargs):
        captured.update(kwargs)
        return kwargs["validator"]({
            "assessment": "Only exact governed values are accepted.",
            "evidence": [{
                "record_index": 0,
                "kind": "behavioral",
                "claim": "The record contains an exact destination port.",
                "matched_literals": ["3389"],
            }],
        })

    monkeypatch.setattr(evidence_selector, "decide_json", fake_decide_json)
    asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[record],
        hypothesis_text="Investigate TCP SYN on ports 3389 and 389",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        objective="Retrieve scanner evidence",
        indicators={},
        detection_rule_refs=[],
    ))

    prompt = json.loads(captured["prompt"])
    assert prompt["grounded_candidate_refs"] == [0]
    with pytest.raises(ValueError, match="non-literal"):
        captured["validator"]({
            "assessment": "Invalid substring citation.",
            "evidence": [{
                "record_index": 0,
                "kind": "behavioral",
                "claim": "Port 389 was present.",
                "matched_literals": ["389"],
            }],
        })
