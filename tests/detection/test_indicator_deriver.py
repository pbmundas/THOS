import json

import pytest

from services.detection import indicator_deriver


@pytest.mark.asyncio
async def test_indicator_derivation_is_schema_bounded_and_literal_grounded(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        indicator_deriver.cache,
        "cache_get",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        indicator_deriver.cache,
        "cache_set",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        indicator_deriver,
        "search_cyber_knowledge",
        lambda _query, limit, _categories: [
            {
                "citation_id": f"REF:{index}",
                "text": "Event 5156 records an allowed network connection.",
            }
            for index in range(limit)
        ],
    )

    async def fake_generate(**kwargs):
        captured.update(kwargs)
        return json.dumps(
            {
                "event_ids": ["5156", "9999"],
                "keywords": ["nmap.exe", "invented.exe"],
                "behavior_phrases": [
                    "network connection",
                    "unsupported behavior",
                ],
            }
        )

    monkeypatch.setattr(indicator_deriver, "generate", fake_generate)
    monkeypatch.setattr(
        indicator_deriver,
        "get_value",
        lambda _section, key, default=None: {
            "indicator_reference_hit_cap": 2,
            "indicator_reference_char_cap": 900,
            "indicator_transport_retries": 0,
            "indicator_decision_num_predict": 160,
        }.get(key, default),
    )

    result = await indicator_deriver.derive_indicators(
        "An adversary runs nmap.exe to identify a network connection.",
        "T1046",
        "Network Service Discovery",
        "Discovery",
    )

    assert result["event_ids"] == ["5156"]
    assert result["keywords"] == ["nmap.exe"]
    assert result["behavior_phrases"] == ["network connection"]
    assert result["grounding_sources"] == ["REF:0", "REF:1"]
    assert captured["format"] == indicator_deriver.INDICATOR_SCHEMA
    assert captured["transport_retries"] == 0
    assert captured["timeout_seconds"] == 45
    assert captured["num_predict"] == 160
    assert len(captured["prompt"]) < 1800
