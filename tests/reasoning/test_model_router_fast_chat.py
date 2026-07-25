from services.reasoning import model_router


def test_ask_thos_uses_dedicated_fast_tier(monkeypatch):
    monkeypatch.setenv("THOS_MODEL_FAST", "fast-local-model")
    target = model_router.target_for("chat")
    assert target.tier == "fast"
    assert target.model == "fast-local-model"
