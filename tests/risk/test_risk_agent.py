from datetime import datetime, timezone

from services.risk.risk_agent import analyze_actionable_risks


def test_risk_agent_correlates_verified_report_and_detection(tmp_path):
    report = tmp_path / "hunt.md"
    report.write_text(
        """# Threat Hunt Report: Network Discovery

### Security Findings
- [hard-evidence] Evidence of Nmap scripting engine usage (evidence: ref: 0)

### Verifier / Critic Validation
Passed: all citations validated.

```json
{"host": "linux-victim", "src_ip": "172.20.0.5"}
```
""",
        encoding="utf-8",
    )
    now = datetime.now(timezone.utc)
    payload = analyze_actionable_risks(
        [{
            "hunt_id": "hunt-1",
            "hypothesis_id": "H111",
            "status": "completed",
            "report_path": str(report),
            "created_at": now,
            "updated_at": now,
            "outcome": {},
        }],
        [{
            "run_id": "run-1",
            "rule_id": "rule-1",
            "rule_title": "Malware prevented",
            "level": "high",
            "events_matched": 4,
            "matched_events": [{"host": "workstation-1"}],
            "analysis": {"summary": "Four malware events were prevented."},
            "created_at": now,
            "siem_type": "wazuh",
        }],
        tmp_path,
    )

    assert payload["agent"]["id"] == "risk_analysis"
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["affected_entities"] == 2
    report_risk = next(item for item in payload["items"] if item["source_type"] == "hunt_report")
    assert report_risk["entity"] == {"type": "IP address", "name": "172.20.0.5"}
    assert report_risk["report_filename"] == "hunt.md"
    detection_risk = next(item for item in payload["items"] if item["source_type"] == "detection")
    assert detection_risk["detection_run_id"] == "run-1"
    assert detection_risk["severity"] == "high"


def test_risk_agent_excludes_unverified_report_findings(tmp_path):
    report = tmp_path / "unverified.md"
    report.write_text(
        """# Unverified Hunt

### Security Findings
- Suspicious activity with no validated citation
""",
        encoding="utf-8",
    )
    now = datetime.now(timezone.utc)
    payload = analyze_actionable_risks(
        [{
            "hunt_id": "hunt-2",
            "status": "completed",
            "report_path": str(report),
            "created_at": now,
            "updated_at": now,
            "outcome": {},
        }],
        [],
        tmp_path,
    )

    assert payload["items"] == []
    assert payload["summary"]["total"] == 0


def test_risk_agent_excludes_verified_negative_findings(tmp_path):
    report = tmp_path / "negative.md"
    report.write_text(
        """# Negative Hunt

### Security Findings
- [hard-evidence] No evidence of port scanning tools or network discovery
- [hard-evidence] Nmap scripting engine activity was observed (evidence: ref: 0)

### Verifier / Critic Validation
Passed: all citations validated.

```json
{"src_ip": "172.20.0.5"}
```
""",
        encoding="utf-8",
    )
    now = datetime.now(timezone.utc)
    payload = analyze_actionable_risks(
        [{
            "hunt_id": "hunt-3",
            "hypothesis_id": "H111",
            "status": "completed",
            "report_path": str(report),
            "created_at": now,
            "updated_at": now,
            "outcome": {},
        }],
        [],
        tmp_path,
    )

    assert len(payload["items"]) == 1
    assert payload["items"][0]["name"].startswith("Nmap scripting engine")
