from services.reasoning.capabilities import recommend_models, resource_snapshot


def test_capability_recommendations_separate_fast_and_quality_routes(monkeypatch):
    monkeypatch.setenv("THOS_OLLAMA_MEMORY_BUDGET_GB", "12")
    resources = resource_snapshot([])
    models = [
        {"name": "fast:1.5b", "size": 1_000_000_000,
         "details": {"parameter_size": "1.5B", "family": "qwen"}},
        {"name": "cyber:7b", "size": 4_500_000_000,
         "details": {"parameter_size": "7B", "family": "qwen"}},
        {"name": "nomic-embed-text", "size": 300_000_000,
         "details": {"parameter_size": "0.3B", "family": "nomic-bert"}},
    ]

    result = recommend_models(
        models,
        {"evidence_selector": "fast", "reasoning": "cyber"},
        resources,
    )

    assert result["evidence_selector"]["model"] == "fast:1.5b"
    assert result["reasoning"]["model"] == "cyber:7b"
    assert all("embed" not in item["model"] for item in result.values())
