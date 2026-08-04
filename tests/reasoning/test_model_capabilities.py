from services.reasoning.capabilities import recommend_models, resource_snapshot


def test_capability_recommendations_separate_fast_and_quality_routes(monkeypatch):
    monkeypatch.setenv("THOS_OLLAMA_MEMORY_BUDGET_GB", "12")
    resources = resource_snapshot([])
    models = [
        {"name": "richardyoung/llama-3.1-8b-instruct-abliterated:Q4_K_M",
         "size": 4_900_000_000,
         "details": {"parameter_size": "8B", "family": "llama"}},
        {"name": "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",
         "size": 5_000_000_000,
         "details": {"parameter_size": "8.1B", "family": "foundation-sec"}},
        {"name": "nomic-embed-text", "size": 300_000_000,
         "details": {"parameter_size": "0.3B", "family": "nomic-bert"}},
    ]

    result = recommend_models(
        models,
        {"evidence_selector": "fast", "reasoning": "cyber"},
        resources,
    )

    assert result["evidence_selector"]["model"] == (
        "richardyoung/llama-3.1-8b-instruct-abliterated:Q4_K_M"
    )
    assert result["reasoning"]["model"] == (
        "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
    )
    assert all("embed" not in item["model"] for item in result.values())
