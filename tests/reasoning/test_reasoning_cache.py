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
            "findings": [],
            "recommendations": "Continue monitoring.",
            "need_more_logs": False,
            "follow_up_query": None,
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
    assert {k: v for k, v in first.items() if k != "reasoning_cache_hit"} == {
        k: v for k, v in second.items() if k != "reasoning_cache_hit"
    }
    assert model_calls == 1
