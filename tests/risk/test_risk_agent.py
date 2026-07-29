import asyncio
from datetime import datetime, timezone

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

    async def decide(**kwargs):
        candidate_id = "report:hunt-1:0"
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
            "outcome": {},
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
