import json

import pytest

from services.knowledge import cyber_corpus, cyber_retrieval


MANIFEST = "data/knowledge_sources/cybersecurity_sources.json"


def test_manifest_allows_only_governed_sources():
    sources = cyber_corpus.load_manifest(MANIFEST)

    assert len(sources) >= 8
    assert all(source.license for source in sources)
    assert all(source.trust_tier in cyber_corpus.ALLOWED_TRUST_TIERS for source in sources)
    licensed = next(source for source in sources if source.id == "organization_licensed_material")
    assert licensed.enabled is False
    assert licensed.license == "PROPRIETARY-LICENSE-REQUIRED"


def test_manifest_rejects_enabled_proprietary_material(tmp_path):
    payload = json.loads(open(MANIFEST, encoding="utf-8").read())
    source = next(
        item for item in payload["sources"]
        if item["id"] == "organization_licensed_material"
    )
    source["enabled"] = True
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(cyber_corpus.CorpusPolicyError, match="proprietary material"):
        cyber_corpus.load_manifest(path)


def test_attack_and_kev_json_are_converted_to_independent_records():
    source = cyber_corpus.Source(
        id="test_source", title="Test", enabled=True, required=True, kind="json",
        location="https://www.cisa.gov/test.json", publisher="Test",
        license="U.S. Government Work", license_url="https://www.cisa.gov",
        trust_tier="primary", domains=("threat_detection",), refresh_days=1,
    )
    attack = cyber_corpus._json_documents(source, json.dumps({
        "objects": [{
            "id": "attack-pattern--1",
            "type": "attack-pattern",
            "name": "Credential Dumping",
            "description": "Adversaries may dump credentials.",
            "external_references": [{"external_id": "T1003"}],
        }, {
            "id": "relationship--1",
            "type": "relationship",
            "description": "Graph plumbing should not enter the corpus.",
        }],
    }).encode())
    kev = cyber_corpus._json_documents(source, json.dumps({
        "vulnerabilities": [{
            "cveID": "CVE-2026-0001",
            "vulnerabilityName": "Example vulnerability",
            "shortDescription": "Actively exploited.",
            "requiredAction": "Apply mitigations.",
        }]
    }).encode())

    assert attack[0]["title"] == "Credential Dumping"
    assert attack[0]["record_id"] == "T1003"
    assert "Adversaries may dump credentials" in attack[0]["text"]
    assert len(attack) == 1
    assert kev[0]["record_id"] == "CVE-2026-0001"
    assert "Apply mitigations" in kev[0]["text"]


class _FakeCollection:
    def count(self):
        return 2

    def query(self, **_kwargs):
        return {
            "documents": [[
                "Credential dumping can target operating system credential stores.",
                "Unrelated material.",
            ]],
            "metadatas": [[{
                "citation_id": "CYBER:mitre_attack_enterprise:T1003:0",
                "source_id": "mitre_attack_enterprise",
                "source_title": "MITRE ATT&CK Enterprise",
                "record_title": "Credential Dumping",
                "publisher": "MITRE",
                "license": "MITRE ATT&CK Terms of Use",
                "license_url": "https://attack.mitre.org/resources/terms-of-use/",
                "retrieved_at": "2026-07-25T00:00:00Z",
                "trust_tier": "primary",
                "domains": "threat_hunting,threat_detection",
            }, {
                "citation_id": "not-governed",
                "domains": "unknown",
            }]],
            "distances": [[0.2, 0.1]],
        }


def test_retrieval_returns_only_provenance_labelled_hits(monkeypatch):
    monkeypatch.setattr(cyber_retrieval, "get_or_create_collection", lambda _name: _FakeCollection())

    hits = cyber_retrieval.search("How is credential dumping detected?", n_results=5)

    assert len(hits) == 1
    assert hits[0]["citation_id"] == "CYBER:mitre_attack_enterprise:T1003:0"
    assert hits[0]["source"]["publisher"] == "MITRE"
    assert hits[0]["source"]["license"] == "MITRE ATT&CK Terms of Use"
