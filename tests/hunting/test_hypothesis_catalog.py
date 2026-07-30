import json
from pathlib import Path
import re

from services.hunting import hearth
from services.hunting.hypothesis_catalog import (
    canonical_hypotheses,
    hypothesis_document,
    hypothesis_metadata,
    metadata_to_hypothesis,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "data/knowledge_base/hearth/hearth_full.json"
MITRE_GAP_PATH = (
    REPO_ROOT / "services/knowledge/data/mitre_gap_techniques.json"
)


def _source_items():
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def test_versioned_catalog_restores_only_established_b_h_m_hypotheses():
    items = canonical_hypotheses(_source_items())
    prefixes = {
        prefix: sum(item["id"].startswith(prefix) for item in items)
        for prefix in ("B", "H", "M")
    }

    assert len(items) == 306
    assert prefixes == {"B": 33, "H": 247, "M": 26}
    assert len({item["id"] for item in items}) == len(items)
    assert all(re.fullmatch(r"[BHM]\d+", item["id"]) for item in items)
    assert not any(item["id"].startswith("THOS-GAP-") for item in items)


def test_every_hypothesis_has_searchable_technique_name_tags():
    items = canonical_hypotheses(_source_items())

    assert all(item["technique_names"] for item in items)
    assert all(item["vendor_agnostic"] is True for item in items)
    assert all(
        set(item["technique_names"]).issubset(set(item["tags"]))
        for item in items
    )
    assert all(
        "Unmapped ATT&CK technique" not in item["technique_names"]
        for item in items
    )
    assert all("vendor-agnostic" in item["tags"] for item in items)
    assert "wazuh" not in json.dumps(items).casefold()


def test_every_hypothesis_has_vendor_neutral_confirmed_finding_severity():
    items = canonical_hypotheses(_source_items())

    assert all(
        item["severity"] in {"low", "medium", "high", "critical"}
        for item in items
    )
    assert all(0 <= item["severity_score"] <= 100 for item in items)
    assert all(item["severity_rationale"] for item in items)
    assert all(
        item["risk_parameters"]["vendor_agnostic"] is True
        for item in items
    )
    assert all(
        item["risk_parameters"]["classification_basis"]
        == "The hypothesis produced a validated positive finding."
        for item in items
    )
    assert all(
        set(item["risk_parameters"]["review_parameters"])
        == {
            "asset_criticality",
            "blast_radius",
            "privilege_level",
            "data_sensitivity",
            "evidence_confidence",
            "active_exploitation",
            "business_impact",
        }
        for item in items
    )
    assert not any(item["severity"] == "unrated" for item in items)


def test_severity_policy_is_data_driven_not_hypothesis_or_vendor_specific():
    policy_path = (
        REPO_ROOT
        / "services/hunting/data/hypothesis_severity_policy.json"
    )
    implementation_path = (
        REPO_ROOT / "services/hunting/hypothesis_severity.py"
    )
    combined = (
        policy_path.read_text(encoding="utf-8")
        + implementation_path.read_text(encoding="utf-8")
    ).casefold()

    assert not re.search(r"\b[bhm]-?\d{1,3}\b", combined)
    assert not any(
        vendor in combined
        for vendor in ("wazuh", "splunk", "sentinel", "qradar", "elastic")
    )


def test_legacy_catalog_enrichment_is_data_driven():
    items = {item["id"]: item for item in _source_items()}
    expected = {
        "M001": "T1078",
        "M002": "T1071.004",
        "M003": "T1041",
        "M004": "T1565.001",
        "M005": "T1027",
        "B016": "T1497.001",
    }

    assert {
        item_id: items[item_id]["technique"] for item_id in expected
    } == expected
    assert items["M026"]["technique_names"] == [
        "Cross-technique Alert Triage"
    ]

    normalizer = (
        REPO_ROOT / "services/hunting/hypothesis_catalog.py"
    ).read_text(encoding="utf-8")
    assert not any(item_id in normalizer for item_id in [*expected, "M026"])
    assert "TECHNIQUE_NAME_OVERRIDES" not in normalizer
    assert "LEGACY_TECHNIQUE" not in normalizer


def test_missing_attack_names_are_supplied_by_governed_metadata():
    attack = json.loads(MITRE_GAP_PATH.read_text(encoding="utf-8"))
    expected = {
        "T1025": "Data from Removable Media",
        "T1120": "Peripheral Device Discovery",
        "T1132.001": "Standard Encoding",
        "T1210": "Exploitation of Remote Services",
        "T1561.001": "Disk Content Wipe",
        "T1561.002": "Disk Structure Wipe",
        "T1602.001": "SNMP",
        "T1602.002": "Network Device Configuration Dump",
        "T1622": "Debugger Evasion",
    }

    assert {
        technique_id: attack[technique_id]["name"]
        for technique_id in expected
    } == expected


def test_search_metadata_round_trip_preserves_all_technique_names():
    item = next(
        item for item in canonical_hypotheses(_source_items())
        if len(item["techniques"]) > 1
    )
    restored = metadata_to_hypothesis(hypothesis_metadata(item))

    assert restored["techniques"] == item["techniques"]
    assert restored["technique_names"] == item["technique_names"]
    assert restored["all_tactics"] == item["all_tactics"]
    assert restored["severity"] == item["severity"]
    assert restored["severity_score"] == item["severity_score"]
    assert restored["risk_parameters"] == item["risk_parameters"]
    assert set(restored["technique_names"]).issubset(restored["tags"])
    assert all(name in hypothesis_document(item) for name in item["technique_names"])


def test_runtime_catalog_filters_retired_generated_entries(monkeypatch):
    source = canonical_hypotheses(_source_items())[0]
    generated = {
        "id": "THOS-GAP-T1007",
        "title": "Generated vendor entry",
        "text": "Hunt Wazuh telemetry.",
        "technique": "T1007",
    }

    class Collection:
        def count(self):
            return 2

        def get(self, **_kwargs):
            return {
                "metadatas": [
                    hypothesis_metadata(source),
                    hypothesis_metadata(generated),
                ]
            }

    monkeypatch.setattr(hearth, "get_or_create_collection", lambda _name: Collection())

    results = hearth.list_hypotheses()

    assert [item["id"] for item in results] == [source["id"]]


def test_semantic_search_filters_retired_entries_and_returns_named_tags(
    monkeypatch,
):
    source = canonical_hypotheses(_source_items())[0]
    generated = {
        "id": "THOS-GAP-T1007",
        "title": "Generated vendor entry",
        "text": "Hunt Wazuh telemetry.",
        "technique": "T1007",
    }

    class Collection:
        def count(self):
            return 2

        def query(self, **_kwargs):
            return {
                "documents": [["vendor result", hypothesis_document(source)]],
                "metadatas": [[
                    hypothesis_metadata(generated),
                    hypothesis_metadata(source),
                ]],
            }

    monkeypatch.setattr(hearth, "get_or_create_collection", lambda _name: Collection())

    results = hearth.semantic_search_hypotheses("technique name", n_results=1)

    assert len(results) == 1
    assert results[0]["meta"]["id"] == source["id"]
    assert results[0]["meta"]["technique_names"] == source["technique_names"]


def test_ui_searches_and_displays_technique_names_and_tags():
    source = (REPO_ROOT / "services/ui/src/App.jsx").read_text(encoding="utf-8")

    assert "item.technique_names" in source
    assert "item.tags" in source
    assert "ATT&amp;CK technique names" in source


def test_generated_wazuh_overlay_artifacts_are_removed():
    assert not (
        REPO_ROOT / "services/hunting/data/required_gap_hypotheses.json"
    ).exists()
    assert not (
        REPO_ROOT / "scripts/generate-hypothesis-gap-catalog.py"
    ).exists()
