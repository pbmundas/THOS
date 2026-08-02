import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from services.api import ui_gateway
from services.api import control_plane


def test_upstream_timeout_becomes_controlled_gateway_timeout(monkeypatch):
    class TimeoutClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def request(self, *_args, **_kwargs):
            raise httpx.ReadTimeout("slow orchestrator")

    monkeypatch.setattr(ui_gateway.httpx, "AsyncClient", TimeoutClient)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(ui_gateway._upstream_json("GET", "/risks"))

    assert exc_info.value.status_code == 504
    assert exc_info.value.detail == "Orchestrator request timed out for /risks"


def test_risk_route_uses_extended_local_model_timeout(monkeypatch):
    captured = {}

    async def upstream(method, path, **kwargs):
        captured.update({"method": method, "path": path, **kwargs})
        return {"items": []}

    monkeypatch.setattr(ui_gateway, "_upstream_json", upstream)
    request = SimpleNamespace(
        state=SimpleNamespace(role="Expert", permissions={"reports"})
    )

    result = asyncio.run(
        ui_gateway.actionable_risks(request, limit=1000, hours=24)
    )

    assert result == {"items": []}
    assert captured["method"] == "GET"
    assert captured["path"] == "/risks"
    assert captured["upstream_timeout"].read == 300.0
    assert captured["params"] == {
        "limit": 1000,
        "hours": 24,
        "refresh": False,
    }


def test_unrated_catalog_hypotheses_are_valid_schedule_targets():
    assert control_plane.hypothesis_severity({"id": "H111"}) == "unrated"

    payload = control_plane.ScheduleRequest(
        target_id="H111",
        target_ids=["H111"],
        schedule_scope="individual",
        severity="unrated",
        time="01:00",
        siem_type="wazuh",
        siem_types=["wazuh"],
    )

    assert payload.severity == "unrated"


def test_schedule_catalog_view_excludes_removed_vendor_specific_targets():
    schedule = {
        "id": "schedule-1",
        "title": "High severity rotation (3 hypotheses)",
        "target_id": "B001",
        "target_ids": ["B001", "THOS-GAP-T1007", "H111"],
        "hypothesis_targets": [
            {"id": "B001"},
            {"id": "THOS-GAP-T1007"},
            {"id": "H111"},
        ],
    }
    catalog = {
        "B001": {"id": "B001", "title": "Baseline network traffic"},
        "H111": {"id": "H111", "title": "Network service discovery"},
    }

    result = control_plane._reconcile_hypothesis_schedule(schedule, catalog)

    assert result["target_ids"] == ["B001", "H111"]
    assert result["target_count"] == 2
    assert result["title"] == "High severity rotation (2 active hypotheses)"
    assert result["catalog_reconciliation"] == {
        "scheduled_target_count": 3,
        "active_target_count": 2,
        "removed_target_count": 1,
    }
    assert schedule["target_ids"] == ["B001", "THOS-GAP-T1007", "H111"]
