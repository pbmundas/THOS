import asyncio
from datetime import datetime

from services.api import control_plane
from services.api.control_plane import _schedule_is_due, _schema_refresh_is_due


def _at(hour: int, minute: int, day: int = 20) -> datetime:
    return datetime(2026, 7, day, hour, minute)


def test_minute_interval_uses_anchor_and_bounds_to_selected_days():
    item = {"time": "02:00", "frequency": "minutes", "interval": 15, "days": list(range(7))}
    assert _schedule_is_due(item, _at(2, 15))
    assert not _schedule_is_due(item, _at(2, 14))


def test_hour_interval_preserves_anchor_minute():
    item = {"time": "02:20", "frequency": "hourly", "interval": 3, "days": list(range(7))}
    assert _schedule_is_due(item, _at(5, 20))
    assert not _schedule_is_due(item, _at(5, 21))


def test_daily_count_is_evenly_distributed_from_anchor():
    item = {"time": "02:00", "frequency": "daily", "interval": 2, "days": list(range(7))}
    assert _schedule_is_due(item, _at(2, 0))
    assert _schedule_is_due(item, _at(14, 0))
    assert not _schedule_is_due(item, _at(8, 0))


def test_legacy_schedule_remains_once_daily():
    item = {"time": "09:30", "days": list(range(7))}
    assert _schedule_is_due(item, _at(9, 30))
    assert not _schedule_is_due(item, _at(9, 31))


def test_weekly_schema_refresh_is_due_only_for_live_siem():
    now = _at(9, 30)
    base = {
        "general": {"default_siem": "wazuh"},
        "siem": {"wazuh": {"connection_status": "connected"}},
        "maintenance": {
            "schema_refresh_enabled": True,
            "schema_refresh_interval_hours": 168,
            "schema_refresh_last_status": "completed",
            "schema_refresh_last_completed_at": now.replace(day=now.day - 7).isoformat(),
        },
    }

    assert _schema_refresh_is_due(base, now)
    base["siem"]["wazuh"]["connection_status"] = "failed"
    assert not _schema_refresh_is_due(base, now)


def test_scheduled_hypotheses_serialize_to_match_orchestrator_capacity(monkeypatch):
    active = 0
    maximum = 0

    async def fake_execute(_item):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0)
        active -= 1

    async def run_all():
        await asyncio.gather(
            *(control_plane._execute_schedule({"kind": "hypothesis"}) for _ in range(4))
        )

    monkeypatch.setattr(control_plane, "_execute_schedule_unlocked", fake_execute)
    asyncio.run(run_all())

    assert maximum == 1


def test_adaptive_batch_is_owned_by_scheduler_agent(monkeypatch):
    targets = [
        {"id": "low-new", "severity": "low"},
        {"id": "high-recent", "severity": "high"},
        {"id": "critical-never", "severity": "critical"},
        {"id": "high-old", "severity": "high"},
    ]
    item = {
        "severity": "all",
        "run_batch_size": 4,
        "run_batch_max": 4,
        "maintenance_window_minutes": 80,
        "target_run_history": {
            "high-recent": {"last_completed_at": "2026-07-26T10:00:00+05:30"},
            "high-old": {"last_completed_at": "2026-07-20T10:00:00+05:30"},
        },
    }
    duration_rows = [
        {"hypothesis_id": target["id"], "p95_duration_ms": 20 * 60_000}
        for target in targets
    ]
    async def selected_by_agent(**kwargs):
        assert kwargs["capacity"]["ollama_memory_ratio"] == 0.85
        return [targets[2], targets[3]], {
            "adaptive_batch_size": 2,
            "selection_owner": "schedule_planner_model",
        }

    monkeypatch.setattr(
        control_plane, "select_scheduled_targets", selected_by_agent
    )
    selected, plan = asyncio.run(
        control_plane._adaptive_hypothesis_targets(
            item,
            targets,
            duration_rows,
            [],
            {
                "queue_depth": 1,
                "ollama_memory_ratio": 0.85,
                "siem_p95_ms": 7000,
            },
        )
    )

    assert [target["id"] for target in selected] == [
        "critical-never", "high-old",
    ]
    assert plan["adaptive_batch_size"] == 2
    assert plan["selection_owner"] == "schedule_planner_model"
