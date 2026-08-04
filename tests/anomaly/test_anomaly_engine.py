from datetime import datetime, timedelta, timezone

from services.anomaly.engine import build_observations, evaluate_anomalies


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def _observation(value=20, metric="authentication"):
    return {
        "source": "wazuh",
        "bucket_start": NOW,
        "detector_id": "entity_activity_spike",
        "entity_type": "user",
        "entity_name": "alice",
        "metric": metric,
        "value": value,
        "evidence": [{"record_index": 0, "detail": "bounded evidence"}],
    }


def _history(detector="entity_activity_spike", metric="authentication", buckets=24, value=2):
    return [
        {
            "source": "wazuh",
            "bucket_start": NOW - timedelta(minutes=15 * (index + 1)),
            "detector_id": detector,
            "entity_type": "user",
            "entity_name": "alice",
            "metric": metric,
            "value": value,
        }
        for index in range(buckets)
    ]


def test_spike_does_not_create_lead_before_baseline_warms():
    assert evaluate_anomalies([_observation()], _history(buckets=23)) == []


def test_spike_creates_explainable_stable_lead_after_warmup():
    leads = evaluate_anomalies([_observation()], _history())

    assert len(leads) == 1
    assert leads[0]["lead_id"].startswith("ANOM-")
    assert leads[0]["observed"] == 20
    assert leads[0]["expected"] == 2
    assert leads[0]["baseline"]["bucket_count"] == 24
    assert leads[0]["evidence"][0]["record_index"] == 0
    assert "rarity as proof" in leads[0]["hypothesis_text"]


def test_new_user_host_relationship_requires_entity_history_and_repetition():
    current = {
        "source": "wazuh",
        "bucket_start": NOW,
        "detector_id": "new_user_host_relationship",
        "entity_type": "user",
        "entity_name": "alice",
        "metric": "host:new-server",
        "value": 2,
        "evidence": [],
    }
    history = _history(
        detector="new_user_host_relationship",
        metric="host:known-server",
    )

    leads = evaluate_anomalies([current], history)

    assert len(leads) == 1
    assert leads[0]["baseline"]["method"] == "new_edge"
    assert "new-server" in leads[0]["title"]


def test_observation_builder_bounds_evidence_and_tracks_entities():
    records = [
        {
            "timestamp": f"2026-08-05T12:00:{index:02d}Z",
            "host": "server-1",
            "user": "alice",
            "src_ip": "192.0.2.10",
            "event": "4624",
            "event_category": "authentication",
            "detail": "successful logon",
            "source_type": "wazuh",
        }
        for index in range(8)
    ]

    observations = build_observations(records, "wazuh", NOW)

    activity = next(
        item for item in observations
        if item["detector_id"] == "entity_activity_spike" and item["entity_type"] == "user"
    )
    relationship = next(
        item for item in observations if item["detector_id"] == "new_user_host_relationship"
    )
    assert activity["value"] == 8
    assert len(activity["evidence"]) == 5
    assert relationship["metric"] == "host:server-1"
