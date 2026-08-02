from services.reasoning import model_router


def test_ask_thos_uses_dedicated_fast_tier(monkeypatch):
    monkeypatch.setenv("THOS_MODEL_FAST", "fast-local-model")
    target = model_router.target_for("chat")
    assert target.tier == "fast"
    assert target.model == "fast-local-model"


def test_guardrail_uses_dedicated_guard_model(monkeypatch):
    monkeypatch.setenv("THOS_MODEL_GUARD", "guard-local-model")
    target = model_router.target_for("guardrail")
    assert target.tier == "guard"
    assert target.model == "guard-local-model"


def test_cyber_tier_has_room_for_evidence_prompt_and_json(monkeypatch):
    monkeypatch.delenv("THOS_CYBER_NUM_CTX", raising=False)
    monkeypatch.delenv("THOS_CYBER_NUM_PREDICT", raising=False)

    target = model_router.target_for("reasoning")

    assert target.tier == "cyber"
    assert target.num_ctx == 16384
    assert target.num_predict == 2048


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


def test_agent_override_selects_admin_model_and_limits(monkeypatch):
    monkeypatch.setattr(model_router, "get_value", lambda *path, default=None: {
        ("model_routing", "agents"): {"reasoning": "cyber"},
        ("model_routing", "default_tier"): "reasoning",
        ("model_routing", "overrides"): {
            "reasoning": {
                "tier": "cyber",
                "model": "security-local:8b",
                "num_ctx": 12288,
                "num_predict": 1400,
            }
        },
        ("model_routing", "auto_select"): False,
        ("model_routing", "auto_assignments"): {},
        ("models", "default_model"): "",
        ("model_routing", "profiles", "cyber"): {
            "num_ctx": 16384,
            "num_predict": 2048,
        },
        ("model_routing", "scheduled_agents"): [],
    }.get(tuple(path), default))

    target = model_router.target_for("reasoning")

    assert target.tier == "cyber"
    assert target.model == "security-local:8b"
    assert target.num_ctx == 12288
    assert target.num_predict == 1400
