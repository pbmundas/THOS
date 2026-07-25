import json

from services.training.dataset_builder import build_sft_records


def _manifest(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "sources": [{
            "id": "approved_source",
            "title": "Approved",
            "enabled": True,
            "required": True,
            "kind": "json",
            "location": "https://www.cisa.gov/example.json",
            "publisher": "CISA",
            "license": "U.S. Government Work",
            "license_url": "https://www.cisa.gov/about/website-policies",
            "trust_tier": "primary",
            "domains": ["incident_response"],
            "refresh_days": 30
        }]
    }), encoding="utf-8")
    return path


def _example(**overrides):
    value = {
        "id": "ir-001",
        "domain": "incident_response",
        "question": "What should be verified before declaring containment?",
        "answer": "Verify the scoped evidence first [CYBER:approved_source:record:0].",
        "human_verified": True,
        "verified_by": "senior-analyst",
        "evidence": [{
            "citation_id": "CYBER:approved_source:record:0",
            "text": "Verify incident scope and evidence.",
            "source": {"id": "approved_source"},
        }],
    }
    value.update(overrides)
    return value


def test_builder_accepts_only_human_verified_grounded_examples(tmp_path):
    records, rejected = build_sft_records([
        _example(),
        _example(id="bad-1", human_verified=False),
        _example(id="bad-2", answer="An uncited assertion."),
    ], _manifest(tmp_path))

    assert len(records) == 1
    assert records[0]["metadata"]["verified_by"] == "senior-analyst"
    assert {item["id"] for item in rejected} == {"bad-1", "bad-2"}


def test_builder_rejects_unapproved_source(tmp_path):
    example = _example()
    example["evidence"][0]["source"]["id"] = "unlicensed_source"

    records, rejected = build_sft_records([example], _manifest(tmp_path))

    assert records == []
    assert "unapproved" in rejected[0]["reason"]
