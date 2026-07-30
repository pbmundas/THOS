import asyncio
import json

from services.reasoning import reasoning


def test_repeated_identical_reasoning_uses_cached_completion(monkeypatch):
    stored = {}
    model_calls = 0

    monkeypatch.setattr(
        reasoning.cache, "cache_get",
        lambda namespace, payload: stored.get((namespace, payload)),
    )
    monkeypatch.setattr(
        reasoning.cache, "cache_set",
        lambda namespace, payload, value: stored.__setitem__((namespace, payload), value),
    )

    async def no_kb_context(state):
        return ""

    async def fake_generate(*args, **kwargs):
        nonlocal model_calls
        model_calls += 1
        return json.dumps({
            "summary": "No suspicious activity found.",
            "findings": [{
                "claim": "The reviewed command is present.",
                "evidence": "cmd.exe was recorded.",
                "ref": "0",
                "confidence": "circumstantial",
            }],
            "recommendations": "Continue monitoring.",
            "need_more_logs": False,
            "follow_up_objective": "",
            "follow_up_source": "",
            "follow_up_lookback_minutes": 0,
            "follow_up_limit": 0,
        })

    monkeypatch.setattr(reasoning, "_build_kb_context", no_kb_context)
    monkeypatch.setattr(reasoning, "generate", fake_generate)
    state = {
        "hypothesis_text": "Repeated hypothesis",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "processed_logs": [{"event": "4688", "detail": "cmd.exe"}],
        "sigma_matched_refs": [],
        "sigma_matched_count": 0,
        "iteration": 0,
        "max_iterations": 3,
    }

    first = asyncio.run(reasoning.reason_node(state))
    second = asyncio.run(reasoning.reason_node(state))

    assert first["reasoning_cache_hit"] is False
    assert second["reasoning_cache_hit"] is True
    assert first["reasoning_attempts"] == 1
    assert second["reasoning_attempts"] == 0
    assert {k: v for k, v in first.items() if k not in {"reasoning_cache_hit", "reasoning_attempts"}} == {
        k: v for k, v in second.items() if k not in {"reasoning_cache_hit", "reasoning_attempts"}
    }
    assert model_calls == 1


def test_reasoning_prompt_is_compact_and_preserves_evidence_refs(monkeypatch):
    captured = {}

    async def no_kb_context(state):
        return ""

    async def fake_generate(prompt, **kwargs):
        captured["prompt"] = prompt
        captured["kwargs"] = kwargs
        return json.dumps({
            "summary": "Grounded network behavior was reviewed.",
            "findings": [{
                "claim": "A destination port is present.",
                "evidence": "destination port 3389",
                "ref": "0",
                "confidence": "hard-evidence",
            }],
            "recommendations": "Validate the originating process.",
            "need_more_logs": False,
            "follow_up_objective": "",
            "follow_up_source": "",
            "follow_up_lookback_minutes": 0,
            "follow_up_limit": 0,
        })

    monkeypatch.setattr(reasoning, "_build_kb_context", no_kb_context)
    monkeypatch.setattr(reasoning, "generate", fake_generate)
    records = [{
        "event": "network",
        "evidence_summary": f"destination port {3389 + index}",
        "detail": "duplicated-detail-" * 1000,
        "full_log": "duplicated-full-log-" * 1000,
        "_raw": {"payload": "duplicated-raw-" * 1000},
    } for index in range(30)]
    attempts = [{
        "source": "siem",
        "objective": "review network discovery",
        "query": "source_query",
        "normalized_query": "normalized_query",
        "total_hits": 30,
    } for _ in range(20)]
    state = {
        "hypothesis_text": "Review network discovery behavior",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "discovery",
        "processed_logs": records,
        "behavioral_evidence": [{"record_index": 0, "claim": "port present"}],
        "evidence_highlights": [],
        "enrichment_hits": [],
        "enrichment": {"sigma_matched_records": 0},
        "sigma_matched_refs": [],
        "sigma_matched_count": 0,
        "retrieval_attempts": attempts,
        "iteration": 0,
        "max_iterations": 1,
    }

    result = asyncio.run(reasoning.reason_node(state))

    assert result["reasoning_failed"] is False
    assert len(captured["prompt"]) < 30000
    assert "\"_ref\":0" in captured["prompt"]
    assert "duplicated-detail" not in captured["prompt"]
    assert "duplicated-full-log" not in captured["prompt"]
    assert "duplicated-raw" not in captured["prompt"]
    assert "\"query\":\"normalized_query\"" in captured["prompt"]
    assert captured["prompt"].count("\"query\":\"normalized_query\"") == 8
    assert captured["kwargs"]["num_predict"] == 512
