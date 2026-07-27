import json
from pathlib import Path

from services.api.control_plane import hypothesis_severity
from services.hunting import hearth
from services.knowledge import mitre


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_required_gap_hypotheses_are_unique_observable_and_mitre_mapped():
    items = hearth.REQUIRED_GAP_HYPOTHESES

    assert len(items) == 116
    assert len({item["id"] for item in items}) == len(items)
    assert len({item["technique"] for item in items}) == len(items)
    assert all(item["runnable_sigma_rules"] > 0 for item in items)
    assert all(item["category"] == "THOS Required Coverage Gap" for item in items)
    assert all(
        mitre.map_technique(item["technique"])["id"] == item["technique"]
        for item in items
    )


def test_required_gap_catalog_does_not_duplicate_hearth_exact_techniques():
    upstream = json.loads(
        (REPO_ROOT / "data/knowledge_base/hearth/hearth_full.json").read_text(
            encoding="utf-8"
        )
    )
    upstream_techniques = {
        technique
        for item in upstream
        for technique in [
            *(item.get("all_techniques") or []),
            item.get("technique"),
        ]
        if technique
    }

    assert not upstream_techniques.intersection(
        item["technique"] for item in hearth.REQUIRED_GAP_HYPOTHESES
    )


def test_new_attack_tactics_receive_risk_appropriate_severity():
    assert hypothesis_severity({"tactic": "Initial Access"}) == "high"
    assert hypothesis_severity({"tactic": "Stealth"}) == "high"
    assert hypothesis_severity({"tactic": "Defense Impairment"}) == "critical"


def test_removed_on_prem_intelligence_copy_does_not_return():
    source = (REPO_ROOT / "services/ui/src/App.jsx").read_text(encoding="utf-8")

    assert "On-prem intelligence" not in source
    assert "Evidence and model inference remain inside your environment." not in source
