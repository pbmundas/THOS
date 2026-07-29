import asyncio
from io import BytesIO
import json

from fastapi import UploadFile
from starlette.requests import Request

from services.api import ui_gateway


def _request() -> Request:
    request = Request({"type": "http", "method": "POST", "path": "/"})
    request.state.analyst = "forensic-analyst"
    request.state.permissions = {"forensics"}
    request.state.role = "Expert"
    return request


def test_spa_route_allowlist_accepts_pages_and_validated_dynamic_ids():
    identifier = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    assert ui_gateway._is_spa_route("/overview") is True
    assert ui_gateway._is_spa_route("/forensic/yara") is True
    assert ui_gateway._is_spa_route(f"/forensic/yara/{identifier}") is True
    assert ui_gateway._is_spa_route("/reports/20260728_report.md") is True
    assert ui_gateway._is_spa_route("/configuration/audit") is True


def test_spa_route_allowlist_rejects_unbounded_or_traversal_paths():
    assert ui_gateway._is_spa_route("/forensic/yara/not-a-uuid") is False
    assert ui_gateway._is_spa_route("/reports/../config.json") is False
    assert ui_gateway._is_spa_route("/configuration/audit/extra") is False
    assert ui_gateway._is_spa_route("/api/reports") is False


def test_suspicious_file_is_preserved_hashed_and_scanned_with_evidence_profile(
    tmp_path, monkeypatch,
):
    captured = {}
    monkeypatch.setattr(ui_gateway, "FORENSIC_ROOT", tmp_path)
    monkeypatch.setattr(ui_gateway, "FORENSIC_MAX_FILE_BYTES", 10_000)
    monkeypatch.setattr(
        ui_gateway.control_plane, "require_feature", lambda *_args, **_kwargs: None,
    )

    async def upstream(method, path, **kwargs):
        captured.update({"method": method, "path": path, **kwargs})
        return {
            "files_scanned": 1,
            "matched_files": 1,
            "match_count": 1,
            "duration_ms": 12,
            "results": [{
                "status": "matched",
                "matches": [{"rule_id": "rule-1", "raw_rule_id": "Example"}],
            }],
            "errors": [],
        }

    monkeypatch.setattr(ui_gateway, "_upstream_json", upstream)
    upload = UploadFile(filename="sample.exe", file=BytesIO(b"MZ suspicious bytes"))

    result = asyncio.run(ui_gateway.create_yara_forensic_scan(
        _request(),
        sample=upload,
        scan_title="Suspicious executable",
        artifact_type="suspicious_file",
        acquired_from="EDR",
        notes="Collected from workstation",
    ))

    assert result["status"] == "matched"
    assert result["sha256"]
    assert captured["path"] == "/yara/scan"
    assert captured["json"]["analysis_profile"] == "evidence"
    preserved = next(tmp_path.rglob("Y0001_sample.exe"))
    assert preserved.read_bytes() == b"MZ suspicious bytes"
    manifest = json.loads(next(tmp_path.rglob("_thos_yara_scan.json")).read_text())
    assert manifest["artifact_type"] == "suspicious_file"
    assert manifest["scan_result"]["match_count"] == 1


def test_memory_dump_uses_large_file_scan_profile(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(ui_gateway, "FORENSIC_ROOT", tmp_path)
    monkeypatch.setattr(ui_gateway, "FORENSIC_MAX_FILE_BYTES", 10_000)
    monkeypatch.setattr(
        ui_gateway.control_plane, "require_feature", lambda *_args, **_kwargs: None,
    )

    async def upstream(_method, _path, **kwargs):
        captured.update(kwargs)
        return {
            "files_scanned": 1,
            "matched_files": 0,
            "match_count": 0,
            "duration_ms": 20,
            "results": [{"status": "clean", "matches": []}],
            "errors": [],
        }

    monkeypatch.setattr(ui_gateway, "_upstream_json", upstream)
    upload = UploadFile(filename="host.raw", file=BytesIO(b"memory image bytes"))

    result = asyncio.run(ui_gateway.create_yara_forensic_scan(
        _request(),
        sample=upload,
        scan_title="Host memory",
        artifact_type="memory_dump",
        acquired_from="WinPmem",
        notes="Incident capture",
    ))

    assert result["status"] == "clean"
    assert captured["json"]["analysis_profile"] == "memory"


def test_forensic_scan_history_returns_persisted_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(ui_gateway, "FORENSIC_ROOT", tmp_path)
    monkeypatch.setattr(
        ui_gateway.control_plane, "require_feature", lambda *_args, **_kwargs: None,
    )
    case = tmp_path / "2026-07-28" / "scan"
    case.mkdir(parents=True)
    (case / "_thos_yara_scan.json").write_text(json.dumps({
        "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "scan_title": "Executable",
        "artifact_type": "suspicious_file",
        "original_name": "sample.exe",
        "status": "matched",
        "scan_result": {"match_count": 2, "duration_ms": 44},
    }))

    items = asyncio.run(ui_gateway.list_yara_forensic_scans(_request()))

    assert items[0]["scan_title"] == "Executable"
    assert items[0]["match_count"] == 2
