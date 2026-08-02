import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from services.risk import risk_agent


def test_risk_agent_uses_model_decision_with_grounded_entity(
    tmp_path, monkeypatch
):
    report = tmp_path / "hunt.md"
    report.write_text(
        """# Threat Hunt Report: Network Discovery

### Security Findings
- [hard-evidence] Nmap scripting engine activity from 172.20.0.5 (evidence: ref: 0)

### Verifier / Critic Validation
Passed: all citations validated.
""",
        encoding="utf-8",
    )
    now = datetime.now(timezone.utc)
    review_systems = []

    async def decide(**kwargs):
        candidate_id = "report:hunt-1:0"
        if kwargs["schema"] is risk_agent.RISK_ELIGIBILITY_SCHEMA:
            return kwargs["validator"]({
                "candidate_id": candidate_id,
                "actionable": True,
                "rationale": "Validated exposure requires detailed scoring.",
            })
        if kwargs["schema"] is risk_agent.RISK_REVIEW_SCHEMA:
            review_systems.append(kwargs["system"])
            return kwargs["validator"]({
                "approved": True,
                "rationale": "The proposed risk is grounded in the evidence.",
            })
        return kwargs["validator"]({
            "items": [{
                "candidate_id": candidate_id,
                "name": "Observed network discovery activity",
                "description": "Validated discovery evidence needs review.",
                "what": "Network service discovery was observed.",
                "why": "It may expose reachable services.",
                "discovery": "A validated hunt report identified it.",
                "entity_type": "IP address",
                "entity_name": "172.20.0.5",
                "score": 72,
                "severity": "high",
                "evidence_refs": [candidate_id],
            }],
            "excluded_candidates": [],
        })

    monkeypatch.setattr(risk_agent, "decide_json", decide)
    payload = asyncio.run(risk_agent.analyze_actionable_risks(
        [{
            "hunt_id": "hunt-1",
            "hypothesis_id": "H111",
            "status": "completed",
            "report_path": str(report),
            "created_at": now,
            "updated_at": now,
            "outcome": {
                "verification_status": "passed",
                "report_status": "generated",
                "reasoning_mode": "model",
                "reasoning_degraded": False,
            },
        }],
        [],
        tmp_path,
    ))

    assert payload["agent"]["id"] == "risk_analysis"
    assert payload["summary"]["total"] == 1
    assert payload["items"][0]["entity"] == {
        "type": "IP address",
        "name": "172.20.0.5",
    }
    assert payload["items"][0]["score"] == 72
    assert "source or initiating actor" in review_systems[0]


def test_unverified_report_never_reaches_risk_model(tmp_path, monkeypatch):
    report = tmp_path / "unverified.md"
    report.write_text(
        "# Hunt\n\n### Security Findings\n- Unsupported finding",
        encoding="utf-8",
    )
    called = False

    async def decide(**_kwargs):
        nonlocal called
        called = True
        return {"items": [], "excluded_candidates": []}

    monkeypatch.setattr(risk_agent, "decide_json", decide)
    payload = asyncio.run(risk_agent.analyze_actionable_risks(
        [{
            "hunt_id": "hunt-2",
            "status": "completed",
            "report_path": str(report),
            "created_at": datetime.now(timezone.utc),
        }],
        [],
        tmp_path,
    ))

    assert called is False
    assert payload["items"] == []


def test_explicitly_negative_verified_report_is_not_a_risk_candidate(tmp_path):
    report = tmp_path / "negative.md"
    report.write_text(
        "# Hunt\n\n### Findings\n- [hard-evidence] No evidence of port scanning was observed",
        encoding="utf-8",
    )
    candidates = risk_agent._report_candidates([{
        "hunt_id": "hunt-negative",
        "status": "completed",
        "report_path": str(report),
        "outcome": {
            "verification_status": "passed",
            "report_status": "generated",
            "reasoning_mode": "model",
            "reasoning_degraded": False,
        },
    }], tmp_path)

    assert candidates == []


def test_legacy_textual_verifier_marker_cannot_seed_risk(tmp_path, monkeypatch):
    report = tmp_path / "legacy.md"
    report.write_text(
        """# Legacy Hunt

### Security Findings
- [hard-evidence] Legacy claim (evidence: ref: 0)

### Verifier / Critic Validation
Passed: citation indexes were present.
""",
        encoding="utf-8",
    )
    called = False

    async def decide(**_kwargs):
        nonlocal called
        called = True
        return {"items": [], "excluded_candidates": []}

    monkeypatch.setattr(risk_agent, "decide_json", decide)
    payload = asyncio.run(risk_agent.analyze_actionable_risks(
        [{
            "hunt_id": "legacy-hunt",
            "status": "completed",
            "report_path": str(report),
            "created_at": datetime.now(timezone.utc),
            "outcome": {
                "report_status": "generated",
                "reasoning_mode": "model",
                "reasoning_degraded": False,
            },
        }],
        [],
        tmp_path,
    ))

    assert called is False
    assert payload["items"] == []


def test_materialized_risk_view_filters_without_model_inference():
    now = datetime.now(timezone.utc)
    payload = {
        "generated_at": now.isoformat(),
        "agent": {"id": "risk_analysis"},
        "items": [
            {
                "id": "new",
                "severity": "high",
                "score": 80,
                "identified_at": now.isoformat(),
                "source_type": "hunt_report",
                "entity": {"type": "host", "name": "server-1"},
            },
            {
                "id": "old",
                "severity": "medium",
                "score": 50,
                "identified_at": (now - timedelta(days=10)).isoformat(),
                "source_type": "detection",
                "entity": {"type": "host", "name": "server-2"},
            },
        ],
    }

    result = risk_agent.filter_risk_payload(payload, limit=10, hours=24)

    assert [item["id"] for item in result["items"]] == ["new"]
    assert result["summary"]["total"] == 1
    assert result["summary"]["high"] == 1
    assert result["summary"]["report_findings"] == 1
    assert result["summary"]["reviewed_candidates"] == 1


def test_resolved_risk_is_retained_as_inactive_and_excluded_from_open_summary():
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "items": [
            {
                "id": "risk-open",
                "severity": "high",
                "score": 80,
                "identified_at": now,
                "source_type": "hunt_report",
                "entity": {"type": "host", "name": "server-1"},
            },
            {
                "id": "risk-resolved",
                "severity": "critical",
                "score": 95,
                "identified_at": now,
                "source_type": "detection",
                "entity": {"type": "user", "name": "analyst-1"},
            },
        ],
    }
    resolutions = [{
        "risk_id": "risk-resolved",
        "status": "resolved",
        "resolved_by": "sme-user",
        "resolved_at": now,
        "note": "Mitigated",
    }]

    overlaid = risk_agent.apply_risk_resolutions(payload, resolutions)
    result = risk_agent.filter_risk_payload(overlaid, limit=10)

    assert len(result["items"]) == 2
    assert result["items"][1]["active"] is False
    assert result["items"][1]["resolved_by"] == "sme-user"
    assert result["summary"]["total"] == 1
    assert result["summary"]["inactive"] == 1
    assert result["summary"]["high"] == 1
    assert result["summary"]["critical"] == 0
    assert result["summary"]["reviewed_candidates"] == 2


def test_risk_source_version_changes_with_persisted_evidence(tmp_path):
    now = datetime.now(timezone.utc)
    report = tmp_path / "hunt.md"
    report.write_text("report-v1", encoding="utf-8")
    hunts = [{
        "hunt_id": "hunt-1",
        "status": "completed",
        "report_path": str(report),
        "updated_at": now,
    }]
    version_one = risk_agent.risk_source_version(hunts, [], tmp_path)
    detections = [{
        "run_id": "detection-1",
        "events_matched": 1,
        "created_at": now,
        "analysis": {"triage": {"priority": "high"}},
    }]

    version_two = risk_agent.risk_source_version(
        hunts, detections, tmp_path
    )

    assert version_one != version_two


def test_detection_candidate_bounds_raw_event_context(monkeypatch):
    monkeypatch.setattr(
        risk_agent,
        "get_value",
        lambda *path, default=None: (
            2 if path[-1] == "risk_detection_event_cap" else default
        ),
    )
    candidates = risk_agent._detection_candidates([{
        "run_id": "run-1",
        "rule_id": "rule-1",
        "events_matched": 3,
        "analysis": {
            "method": "scheduled query",
            "total_hits": 9,
            "triage": {"note": "Rule-title-derived claim"},
            "ai_analysis": {"analysis_lines": ["Unsupported claim"]},
        },
        "matched_events": [
            {
                "host": f"server-{index}",
                "detail": "x" * 2000,
                "duplicated_raw_payload": "y" * 5000,
            }
            for index in range(3)
        ],
    }])

    events = candidates[0]["matched_events"]
    assert len(events) == 2
    assert all(len(event["detail"]) == 800 for event in events)
    assert all("duplicated_raw_payload" not in event for event in events)
    assert candidates[0]["analysis"] == {
        "method": "scheduled query",
        "total_hits": 9,
    }


def test_detection_candidate_requires_rule_title_support_in_raw_events():
    unrelated = {
        "run_id": "run-cron",
        "rule_id": "rule-cron",
        "rule_title": "Modifying Crontab",
        "events_matched": 1,
        "matched_events": [{
            "host": "linux-victim",
            "event": "sca",
            "detail": "CIS check: Ensure LDAP client is not installed.",
        }],
    }
    defender = {
        "run_id": "run-defender",
        "rule_id": "rule-defender",
        "rule_title": "Windows Defender Threat Detected / Blocked",
        "events_matched": 1,
        "matched_events": [{
            "host": "server-1",
            "event": "EventID-1116",
            "detail": "Provider Microsoft-Windows-Windows Defender",
        }],
    }

    candidates = risk_agent._detection_candidates([unrelated, defender])

    assert [item["candidate_id"] for item in candidates] == [
        "detection:run-defender"
    ]


def test_candidate_batches_preserve_complete_json_objects():
    candidates = [
        {"candidate_id": f"candidate-{index}", "detail": "x" * 80}
        for index in range(5)
    ]

    batches = risk_agent._candidate_batches(
        candidates, item_cap=3, prompt_char_cap=250
    )

    assert [item["candidate_id"] for batch in batches for item in batch] == [
        f"candidate-{index}" for index in range(5)
    ]
    assert all(len(batch) <= 3 for batch in batches)


def test_invalid_model_risk_is_dropped_without_losing_grounded_item(
    monkeypatch,
):
    candidates = [{
        "candidate_id": "candidate-valid",
        "source_type": "detection",
        "source_id": "rule-1",
        "entity": "server-1",
    }]

    async def decide(**kwargs):
        if kwargs["schema"] is risk_agent.RISK_ELIGIBILITY_SCHEMA:
            return kwargs["validator"]({
                "candidate_id": "candidate-valid",
                "actionable": True,
                "rationale": "The supplied evidence may describe exposure.",
            })
        if kwargs["schema"] is risk_agent.RISK_REVIEW_SCHEMA:
            return kwargs["validator"]({
                "approved": True,
                "rationale": "The proposal remains evidence-grounded.",
            })
        base = {
            "name": "Observed exposure",
            "description": "Evidence-supported exposure.",
            "what": "A control gap was observed.",
            "why": "The affected server may be exposed.",
            "discovery": "A validated detection identified it.",
            "entity_type": "host",
            "entity_name": "server-1",
            "score": 70,
            "severity": "high",
        }
        return kwargs["validator"]({
            "items": [
                {
                    **base,
                    "candidate_id": "candidate-valid",
                    "evidence_refs": ["candidate-valid"],
                },
                {
                    **base,
                    "candidate_id": "invented-candidate",
                    "evidence_refs": ["invented-candidate"],
                },
            ],
            "excluded_candidates": [],
        })

    monkeypatch.setattr(risk_agent, "decide_json", decide)

    result = asyncio.run(risk_agent._analyze_batch(candidates))

    assert [item["candidate_id"] for item in result["items"]] == [
        "candidate-valid"
    ]


def test_independent_reviewer_can_reject_proposed_risk(monkeypatch):
    candidate_id = "candidate-review"
    candidates = [{
        "candidate_id": candidate_id,
        "source_type": "detection",
        "source_id": "rule-1",
        "entity": "server-1",
    }]

    async def decide(**kwargs):
        if kwargs["schema"] is risk_agent.RISK_ELIGIBILITY_SCHEMA:
            return kwargs["validator"]({
                "actionable": True,
                "rationale": "Initial screening requires a detailed review.",
            })
        if kwargs["schema"] is risk_agent.RISK_REVIEW_SCHEMA:
            return kwargs["validator"]({
                "approved": False,
                "rationale": "The proposal does not establish exposure.",
            })
        return kwargs["validator"]({
            "items": [{
                "candidate_id": candidate_id,
                "name": "Proposed risk",
                "description": "The behavior may be benign.",
                "what": "A routine event was observed.",
                "why": "The evidence does not establish exposure.",
                "discovery": "A detection produced the candidate.",
                "entity_type": "host",
                "entity_name": "server-1",
                "score": 40,
                "severity": "medium",
                "evidence_refs": [candidate_id],
            }],
            "excluded_candidates": [],
        })

    monkeypatch.setattr(risk_agent, "decide_json", decide)

    result = asyncio.run(risk_agent._analyze_batch(candidates))

    assert result["items"] == []
    assert result["excluded_candidates"] == [candidate_id]


def test_risk_model_must_decide_every_candidate(monkeypatch):
    candidates = [{
        "candidate_id": "candidate-required",
        "source_type": "detection",
        "source_id": "rule-1",
        "entity": "server-1",
    }]

    async def decide(**kwargs):
        if kwargs["schema"] is risk_agent.RISK_ELIGIBILITY_SCHEMA:
            return kwargs["validator"]({
                "candidate_id": "candidate-required",
                "actionable": True,
                "rationale": "The candidate requires a complete decision.",
            })
        if kwargs["schema"] is risk_agent.RISK_REVIEW_SCHEMA:
            return kwargs["validator"]({
                "approved": True,
                "rationale": "The proposal remains evidence-grounded.",
            })
        return kwargs["validator"]({
            "items": [],
            "excluded_candidates": [],
        })

    monkeypatch.setattr(risk_agent, "decide_json", decide)

    with pytest.raises(ValueError, match="decision omitted candidate"):
        asyncio.run(risk_agent._analyze_batch(candidates))


def test_risk_candidate_cap_bounds_model_work(monkeypatch):
    seen = []

    async def analyze(batch):
        seen.extend(item["candidate_id"] for item in batch)
        return {"items": [], "excluded_candidates": []}

    settings = {
        "risk_candidate_cap": 2,
        "risk_batch_size": 1,
        "risk_prompt_char_cap": 8_000,
        "risk_batch_concurrency": 1,
    }
    monkeypatch.setattr(risk_agent, "_analyze_batch", analyze)
    monkeypatch.setattr(
        risk_agent,
        "get_value",
        lambda *path, default=None: settings.get(path[-1], default),
    )
    now = datetime.now(timezone.utc)
    detections = [
        {
            "run_id": f"run-{index}",
            "rule_id": f"rule-{index}",
            "status": "detected",
            "events_matched": 1,
            "created_at": now - timedelta(minutes=index),
        }
        for index in range(4)
    ]

    asyncio.run(risk_agent.analyze_actionable_risks([], detections, "."))

    assert seen == ["detection:run-0", "detection:run-1"]


def test_unchanged_excluded_candidate_skips_repeat_model_work(monkeypatch):
    calls = 0

    async def analyze(batch):
        nonlocal calls
        calls += 1
        return {
            "items": [],
            "excluded_candidates": [item["candidate_id"] for item in batch],
        }

    settings = {
        "risk_candidate_cap": 16,
        "risk_batch_size": 4,
        "risk_prompt_char_cap": 12_000,
        "risk_batch_concurrency": 1,
    }
    monkeypatch.setattr(risk_agent, "_analyze_batch", analyze)
    monkeypatch.setattr(
        risk_agent,
        "get_value",
        lambda *path, default=None: settings.get(path[-1], default),
    )
    detection = {
        "run_id": "stable-run",
        "rule_id": "stable-rule",
        "events_matched": 1,
        "created_at": datetime.now(timezone.utc),
        "matched_events": [{"host": "server-1"}],
    }

    first = asyncio.run(risk_agent.analyze_actionable_risks(
        [], [detection], "."
    ))
    second = asyncio.run(risk_agent.analyze_actionable_risks(
        [], [detection], ".", previous_payload=first
    ))

    assert calls == 1
    assert second["items"] == []
    assert second["_excluded_candidate_ids"] == ["detection:stable-run"]


def test_failed_risk_batch_is_retried_per_candidate(monkeypatch):
    call_sizes = []

    async def analyze(batch):
        call_sizes.append(len(batch))
        if len(batch) > 1:
            raise risk_agent.AgentDecisionError("response exceeded output budget")
        return {
            "items": [],
            "excluded_candidates": [batch[0]["candidate_id"]],
        }

    settings = {
        "risk_candidate_cap": 16,
        "risk_batch_size": 2,
        "risk_prompt_char_cap": 12_000,
        "risk_batch_concurrency": 1,
    }
    monkeypatch.setattr(risk_agent, "_analyze_batch", analyze)
    monkeypatch.setattr(
        risk_agent,
        "get_value",
        lambda *path, default=None: settings.get(path[-1], default),
    )
    now = datetime.now(timezone.utc)
    detections = [{
        "run_id": f"run-{index}",
        "rule_id": f"rule-{index}",
        "events_matched": 1,
        "created_at": now - timedelta(seconds=index),
    } for index in range(2)]

    payload = asyncio.run(risk_agent.analyze_actionable_risks(
        [], detections, "."
    ))

    assert call_sizes == [2, 1, 1]
    assert payload["agent"]["degraded"] is False
    assert payload["_excluded_candidate_ids"] == [
        "detection:run-0",
        "detection:run-1",
    ]


def test_detail_failure_is_reconsidered_by_model(monkeypatch):
    eligibility_calls = 0

    async def eligibility(_candidate, **_kwargs):
        nonlocal eligibility_calls
        eligibility_calls += 1
        return {
            "actionable": eligibility_calls == 1,
            "rationale": "Reconsider after detail validation.",
        }

    async def fail_detail(**_kwargs):
        raise risk_agent.AgentDecisionError("entity could not be grounded")

    monkeypatch.setattr(risk_agent, "_eligibility_decision", eligibility)
    monkeypatch.setattr(risk_agent, "decide_json", fail_detail)

    result = asyncio.run(risk_agent._analyze_batch([{
        "candidate_id": "candidate-reconsidered",
        "source_type": "hunt_report",
        "source_id": "hunt-1",
    }]))

    assert eligibility_calls == 2
    assert result == {
        "items": [],
        "excluded_candidates": ["candidate-reconsidered"],
    }
