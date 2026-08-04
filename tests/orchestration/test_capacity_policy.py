import threading

import pytest

from services import capacity


def test_siem_policy_clamps_every_request_to_source_budget():
    config = {
        "siem_retrieval": {
            "default_max_rows": 500,
            "default_concurrent_requests": 2,
            "queue_timeout_seconds": 30,
            "sources": {
                "wazuh": {"max_rows": 250, "concurrent_requests": 1},
            },
        }
    }

    policy = capacity.siem_retrieval_policy("wazuh", 2000, config)

    assert policy["requested_rows"] == 2000
    assert policy["applied_rows"] == 250
    assert policy["capped"] is True
    assert policy["concurrent_requests"] == 1


def test_local_folder_has_separate_non_siem_budget():
    policy = capacity.siem_retrieval_policy(
        "folder", 20_000, {"siem_retrieval": {"folder_max_rows": 8000}},
    )

    assert policy["applied_rows"] == 8000
    assert policy["operator_controlled"] is False


def test_hardware_profile_uses_cgroup_visible_capacity(monkeypatch):
    monkeypatch.setattr(capacity, "_visible_cpus", lambda: 16)
    monkeypatch.setattr(capacity, "_visible_memory_bytes", lambda: 64 * 1024**3)

    profile = capacity.hardware_capacity({
        "capacity": {"auto_scale": True, "profile_override": "auto"},
    })

    assert profile["effective_profile"] == "enterprise"
    assert profile["recommended"]["forensic_concurrency"] == 8
    assert profile["recommended"]["postgres_pool_max"] == 20


def test_siem_gate_times_out_instead_of_exceeding_budget():
    policy = {
        "source": "test-siem",
        "concurrent_requests": 1,
        "queue_timeout_seconds": 1,
    }
    result = []

    with capacity.siem_request_slot(policy):
        worker = threading.Thread(target=lambda: _try_slot(policy, result))
        worker.start()
        worker.join(timeout=2)

    assert result == ["timed_out"]


def _try_slot(policy, result):
    try:
        with capacity.siem_request_slot(policy):
            result.append("entered")
    except TimeoutError:
        result.append("timed_out")
