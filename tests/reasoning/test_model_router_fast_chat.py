from services.reasoning import model_router


def test_ask_thos_uses_dedicated_fast_tier(monkeypatch):
    monkeypatch.setenv("THOS_MODEL_FAST", "fast-local-model")
    target = model_router.target_for("chat")
    assert target.tier == "fast"
    assert target.model == "fast-local-model"


def test_reasoning_tier_has_room_for_evidence_prompt_and_json(monkeypatch):
    monkeypatch.delenv("THOS_REASONING_NUM_CTX", raising=False)
    monkeypatch.delenv("THOS_REASONING_NUM_PREDICT", raising=False)

    target = model_router.target_for("reasoning")

    assert target.num_ctx == 16384
    assert target.num_predict == 4096


def test_scheduled_reasoning_routes_to_dedicated_worker(monkeypatch):
    monkeypatch.setenv("THOS_SCHEDULED_OLLAMA_HOST", "http://ollama-gpu:11434")
    monkeypatch.setenv("THOS_SCHEDULED_MODEL", "scheduled-reasoner")
    token = model_router.set_model_workload("scheduled")
    try:
        target = model_router.target_for("reasoning")
        fast = model_router.target_for("query_gen")
    finally:
        model_router.reset_model_workload(token)

    assert target.host == "http://ollama-gpu:11434"
    assert target.model == "scheduled-reasoner"
    assert fast.host != "http://ollama-gpu:11434"
