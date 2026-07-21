from services.hunting.query_generator import _fallback_query
import json

import pytest

from services.reasoning import reasoning
from services.reasoning.reasoning import _parse_complete_reasoning, _reason_with_three_strikes, ReasoningResponseError


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


def test_folder_query_fallback_is_nonempty():
    assert _fallback_query("Suspicious PowerShell script activity", "folder")
    assert _fallback_query("Suspicious PowerShell script activity", "splunk") == "*"
