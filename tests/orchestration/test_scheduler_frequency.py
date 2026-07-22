from datetime import datetime

from services.api.control_plane import _schedule_is_due


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
