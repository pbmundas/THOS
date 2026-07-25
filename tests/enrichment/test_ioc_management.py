import json
from types import SimpleNamespace

import pytest

from services.api.control_plane import require_feature
from services.enrichment import ioc_management


def test_extract_indicators_from_structured_and_unstructured_content():
    content = json.dumps({
        "objects": [{
            "pattern": "[ipv4-addr:value = '203.0.113.9']",
            "hashes": {"SHA-256": "a" * 64},
            "url": "https://malicious.example/path",
            "case": "CVE-2026-12345",
        }],
    }).encode()

    found = ioc_management.extract_indicators(content, "feed.stix2")

    assert "203.0.113.9" in found["ipv4"]
    assert "a" * 64 in found["sha256"]
    assert "https://malicious.example/path" in found["url"]
    assert "malicious.example" in found["domain"]
    assert "cve-2026-12345" in found["cve"]


@pytest.mark.asyncio
async def test_local_refresh_preserves_snapshot_and_updates_index(tmp_path, monkeypatch):
    local_root = tmp_path / "sources"
    intelligence_root = tmp_path / "intelligence"
    local_root.mkdir()
    source_path = local_root / "provider.any"
    source_path.write_bytes(b"198.51.100.44\nindicator.example\n" + b"b" * 64)
    monkeypatch.setattr(ioc_management, "LOCAL_SOURCE_ROOT", local_root)
    monkeypatch.setattr(ioc_management, "THREAT_INTEL_ROOT", intelligence_root)
    monkeypatch.setattr(ioc_management, "BLOCKLIST_PATH", intelligence_root / "blocklist.json")

    result = await ioc_management.refresh_source({
        "id": "provider-a",
        "name": "Provider A",
        "kind": "local",
        "location": str(source_path),
        "confidence": "high",
    })

    blocklist = json.loads((intelligence_root / "blocklist.json").read_text())
    assert result["extracted_count"] >= 3
    assert result["sha256"]
    assert (intelligence_root / "sources" / "provider-a").is_dir()
    assert blocklist["indicators"]["198.51.100.44"]["confidence"] == "high"
    assert blocklist["indicators"]["indicator.example"]["sources"] == ["provider-a"]


def test_local_refresh_rejects_path_outside_managed_root(tmp_path, monkeypatch):
    local_root = tmp_path / "managed"
    local_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("203.0.113.10")
    monkeypatch.setattr(ioc_management, "LOCAL_SOURCE_ROOT", local_root)

    with pytest.raises(ioc_management.IOCSourceError, match="outside"):
        ioc_management._read_local(str(outside))


def test_role_boundaries_keep_destructive_actions_admin_only():
    admin = SimpleNamespace(state=SimpleNamespace(role="Admin", permissions=set()))
    sme = SimpleNamespace(state=SimpleNamespace(role="SME", permissions=set()))
    expert = SimpleNamespace(state=SimpleNamespace(role="Expert", permissions={"hunts", "reports"}))

    require_feature(admin, "reports", admin_only=True)
    require_feature(sme, "settings", sme_only=True)
    require_feature(expert, "hunts")
    with pytest.raises(Exception) as denied:
        require_feature(sme, "reports", admin_only=True)
    assert getattr(denied.value, "status_code", None) == 403
