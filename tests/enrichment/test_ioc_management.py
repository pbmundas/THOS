import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from services.api import control_plane
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


def test_extracts_and_normalizes_network_indicators():
    found = ioc_management.extract_indicators(b"203.0.113.77/24\n", "feed.netset")

    assert "203.0.113.0/24" in found["network"]
    assert "203.0.113.77" not in found["ipv4"]


def test_dshield_parser_uses_address_and_netmask_without_header_noise():
    found = ioc_management._dshield_networks(
        b"# SANS ISC contact@example.org\n198.51.100.0\t198.51.100.255\t24\t42\n",
    )

    assert found["network"] == {"198.51.100.0/24"}
    assert not any(found[kind] for kind in found if kind != "network")


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
    assert blocklist["indicators"]["indicator.example"]["severity"] == "medium"
    assert blocklist["indicators"]["indicator.example"]["source_details"]["provider-a"]["name"] == "Provider A"


@pytest.mark.asyncio
async def test_successful_refresh_replaces_expired_source_indicators(tmp_path, monkeypatch):
    local_root = tmp_path / "sources"
    intelligence_root = tmp_path / "intelligence"
    local_root.mkdir()
    source_path = local_root / "provider.txt"
    source_path.write_text("expired.example\n", encoding="utf-8")
    monkeypatch.setattr(ioc_management, "LOCAL_SOURCE_ROOT", local_root)
    monkeypatch.setattr(ioc_management, "THREAT_INTEL_ROOT", intelligence_root)
    monkeypatch.setattr(ioc_management, "BLOCKLIST_PATH", intelligence_root / "blocklist.json")
    source = {
        "id": "provider-a", "name": "Provider A", "kind": "local",
        "location": str(source_path), "category": "malware", "severity": "high",
        "confidence": "high",
    }

    await ioc_management.refresh_source(source)
    source_path.write_text("current.example\n", encoding="utf-8")
    await ioc_management.refresh_source(source)

    blocklist = ioc_management.load_blocklist()["indicators"]
    assert "expired.example" not in blocklist
    assert blocklist["current.example"]["category"] == "malware"


@pytest.mark.asyncio
async def test_threat_intelligence_catalog_orders_by_freshness_then_severity(monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(ioc_management, "load_blocklist", lambda: {
        "indicator_count": 3,
        "updated_at": now.isoformat(),
        "indicators": {
            "older-critical.example": {
                "type": "domain", "category": "malware", "categories": ["malware"],
                "severity": "critical", "confidence": "high",
                "last_seen_by_thos": (now - timedelta(hours=2)).isoformat(),
                "source_name": "Test",
            },
            "fresh-low.example": {
                "type": "domain", "category": "phishing", "categories": ["phishing"],
                "severity": "low", "confidence": "medium",
                "last_seen_by_thos": (now - timedelta(minutes=5)).isoformat(),
                "source_name": "Test",
            },
            "fresh-high.example": {
                "type": "domain", "category": "malware", "categories": ["malware"],
                "severity": "high", "confidence": "high",
                "last_seen_by_thos": (now - timedelta(minutes=5)).isoformat(),
                "source_name": "Test",
            },
        },
    })
    request = SimpleNamespace(
        state=SimpleNamespace(role="Expert", permissions={"threat_intel"}),
    )

    result = await control_plane.list_threat_intelligence_iocs(request)

    assert [item["indicator"] for item in result["items"]] == [
        "fresh-high.example", "fresh-low.example", "older-critical.example",
    ]


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
