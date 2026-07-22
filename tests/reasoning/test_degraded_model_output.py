from services.hunting.query_generator import _fallback_query
import json

import pytest

from services.reasoning import reasoning
from services.reasoning.reasoning import (
    _deterministic_reasoning_fallback,
    _parse_complete_reasoning,
    _reason_with_three_strikes,
    reason_node,
    ReasoningResponseError,
    _sanitize_untrusted_text,
)


def _valid_response():
    return json.dumps({
        "summary": "The available evidence does not confirm malicious PowerShell activity.",
        "findings": [{
            "claim": "No encoded command was present in the reviewed record.",
            "evidence": "The command field contained no encoded-command flag.",
            "ref": "0",
            "confidence": "hard-evidence",
        }],
        "recommendations": "- Continue collecting PowerShell Event ID 4104.",
        "need_more_logs": False,
        "follow_up_query": "",
    })


def test_empty_or_incomplete_reasoning_is_rejected_before_reporting():
    with pytest.raises(ReasoningResponseError, match="empty response"):
        _parse_complete_reasoning("")
    with pytest.raises(ReasoningResponseError, match="invalid JSON"):
        _parse_complete_reasoning('{"summary": "unfinished"')


def test_windows_event_xml_system_element_is_not_prompt_injection():
    xml = '<Event><System><EventID>13</EventID></System></Event>'
    assert _sanitize_untrusted_text(xml) == xml


def test_platform_safety_annotation_cannot_become_report_evidence():
    response = json.loads(_valid_response())
    response["findings"][0]["claim"] = (
        "[THOS-UNTRUSTED-TEXT-ANNOTATION] proves log tampering"
    )
    with pytest.raises(ReasoningResponseError, match="safety annotation"):
        _parse_complete_reasoning(json.dumps(response))


def test_malformed_reasoning_reference_is_retried_before_reporting():
    response = json.loads(_valid_response())
    response["findings"][0]["ref"] = "15) and EventID-1116"
    with pytest.raises(ReasoningResponseError, match="malformed record reference"):
        _parse_complete_reasoning(json.dumps(response))


def test_ollama_schema_avoids_unsupported_regex_grammar():
    ref_schema = reasoning.FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]["ref"]
    assert ref_schema == {"type": "string"}


@pytest.mark.asyncio
async def test_reasoning_retries_until_third_attempt_succeeds(monkeypatch):
    responses = ["", '{"summary": "unfinished"', _valid_response()]

    async def fake_generate(*args, **kwargs):
        assert kwargs["transport_retries"] == 0
        return responses.pop(0)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(reasoning, "generate", fake_generate)
    monkeypatch.setattr(reasoning.asyncio, "sleep", no_sleep)

    raw, parsed, attempts, error = await _reason_with_three_strikes("prompt")

    assert raw
    assert parsed["summary"].startswith("The available evidence")
    assert attempts == 3
    assert error is None


@pytest.mark.asyncio
async def test_reasoning_stops_after_exactly_three_failed_attempts(monkeypatch):
    calls = 0

    async def empty_generate(*args, **kwargs):
        nonlocal calls
        calls += 1
        return ""

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(reasoning, "generate", empty_generate)
    monkeypatch.setattr(reasoning.asyncio, "sleep", no_sleep)

    raw, parsed, attempts, error = await _reason_with_three_strikes("prompt")

    assert raw is None and parsed is None
    assert calls == attempts == 3
    assert "attempt 3" in error


@pytest.mark.asyncio
async def test_three_failed_strikes_suppress_report(monkeypatch):
    async def failed(_prompt):
        return None, None, 3, "attempt 1: timeout; attempt 2: timeout; attempt 3: timeout"

    monkeypatch.setattr(reasoning, "_reason_with_three_strikes", failed)
    monkeypatch.setattr(reasoning.cache, "cache_get", lambda *args, **kwargs: None)
    async def no_kb(*args, **kwargs):
        return ""
    monkeypatch.setattr(reasoning, "_build_kb_context", no_kb)
    result = await reason_node({
        "hypothesis_text": "test", "processed_logs": [{"event": "4104", "detail": "powershell"}],
        "sigma_matched_refs": [0], "sigma_rule_matches": [], "coverage_gaps": [],
        "max_iterations": 1, "iteration": 0,
    })

    assert result["reasoning_failed"] is True
    assert result["reasoning_attempts"] == 3
    assert result["report_status"] == "not_generated"
    assert "Report not generated" in result["reasoning_error"]


def test_folder_query_fallback_is_nonempty():
    assert _fallback_query("Suspicious PowerShell script activity", "folder")
    assert _fallback_query("Suspicious PowerShell script activity", "splunk") == "*"


def test_deterministic_reasoning_fallback_is_complete_and_citation_safe():
    result = _deterministic_reasoning_fallback({
        "processed_logs": [{"event": "1"}, {"event": "4104"}],
        "sigma_matched_refs": [1],
        "sigma_rule_matches": [{"title": "Suspicious PowerShell"}],
        "technique_id": "T1059.001",
        "coverage_gaps": [],
    }, {"1": 1, "4104": 1})

    assert result["summary"]
    assert result["recommendations"]
    assert result["findings"][0]["ref"] == "1"
    assert result["need_more_logs"] is False
