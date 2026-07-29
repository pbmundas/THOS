import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from services.forensics import analysis, report, workflow


def _case(tmp_path):
    root = tmp_path / "forensic"
    case_dir = root / "2026-07-25" / "20260725-0001-example"
    case_dir.mkdir(parents=True)
    evidence = case_dir / "E0001_events.log"
    content = b"2026-07-25T12:00:00Z host-a powershell encodedcommand\n"
    evidence.write_bytes(content)
    manifest = {
        "case_id": "11111111-1111-1111-1111-111111111111",
        "case_title": "Example forensic case",
        "examiner": "analyst",
        "received_at": "2026-07-25T12:01:00+00:00",
        "acquired_from": "validated collection tool",
        "legal_authority": "IR-2026-0042",
        "notes": "Examine the supplied event record.",
        "evidence": [{
            "evidence_id": "E0001",
            "original_name": "events.log",
            "stored_name": evidence.name,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_type": "text/plain",
        }],
    }
    (case_dir / analysis.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    return root, case_dir, evidence


def test_integrity_verification_fails_closed_after_tampering(tmp_path, monkeypatch):
    root, case_dir, evidence = _case(tmp_path)
    monkeypatch.setattr(analysis, "FORENSIC_ROOT", root)

    verified = analysis.verify_evidence(case_dir)
    assert verified["evidence"][0]["verified_sha256"] == verified["evidence"][0]["sha256"]

    evidence.write_bytes(b"tampered")
    with pytest.raises(analysis.ForensicIntegrityError, match="integrity verification failed"):
        analysis.verify_evidence(case_dir)


def test_forensic_workflow_records_named_agents_and_writes_technical_report(tmp_path, monkeypatch):
    root, case_dir, _evidence = _case(tmp_path)
    reports = tmp_path / "reports"
    monkeypatch.setattr(analysis, "FORENSIC_ROOT", root)
    monkeypatch.setattr(report, "REPORTS_DIR", reports)
    async def plan(_verified, _prior=None):
        return {
            "case_objective": "Examine supplied evidence.",
            "artifacts": [{
                "evidence_id": "E0001",
                "reasoning": "Use parsed record evidence.",
                "tools": [],
            }],
        }

    monkeypatch.setattr(workflow, "plan_forensic_tools", plan)
    monkeypatch.setattr(workflow, "analyze_artifacts", lambda verified, _plan: {
        "inventory": [{
            "evidence_id": "E0001", "original_name": "events.log",
            "stored_name": "E0001_events.log", "size_bytes": 58,
            "sha256": verified["evidence"][0]["sha256"], "extension": ".log",
            "magic_hex": "32303236",
        }],
        "records": [{
            "timestamp": "2026-07-25T12:00:00Z", "host": "host-a",
            "user": None, "event": "log", "source_file": "events.log",
            "detail": "powershell encodedcommand", "_record_ref": "E0001:0",
        }],
        "archives": [], "disk_images": [], "warnings": [],
        "static_analysis": [], "forensic_tools": {}, "tool_plan": {},
    })
    monkeypatch.setattr(workflow, "correlate_evidence", lambda triage: {
        "records_analyzed": 1,
        "event_histogram": {"log": 1},
        "indicators": {"ipv4": [], "url": [], "email": [], "cve": [], "sha256": []},
        "detection_rules_evaluated": 0,
        "detection_rule_matches": [],
        "matched_record_refs": [],
        "anomaly_scores": [],
        "yara_scan": {"match_count": 0},
        "ioc_matches": [],
        "attack_techniques": [],
        "attack_techniques_by_ref": {},
        "evidence_facts": [],
        "activity_assessments": [],
    })
    async def interpret(_triage, correlation):
        return {
            **correlation,
            "summary": "The supplied record was examined.",
            "overall_disposition": "inconclusive",
            "proven_facts": [{
                "claim": "The record contains the supplied command text.",
                "evidence_refs": ["E0001:0"],
            }],
            "activity_assessments": [],
            "unresolved_anomalies": ["Execution context was not supplied."],
            "recommendations": ["Collect process context."],
            "interpretation_status": "completed",
        }
    monkeypatch.setattr(
        workflow, "interpret_forensic_evidence", interpret
    )
    monkeypatch.setattr(workflow, "build_timeline", lambda triage, correlation=None: [{
        "timestamp": "2026-07-25T12:00:00Z", "evidence_ref": "E0001:0",
        "host": "host-a", "user": None, "event": "log",
        "source_file": "events.log", "detail": "powershell encodedcommand",
    }])
    events = []

    async def progress(event):
        events.append(event)

    result = asyncio.run(workflow.run_forensic_case(str(case_dir), progress))

    completed = [event for event in events if event["event"] == "agent_complete"]
    assert [event["agent_name"] for event in completed] == [
        "Forensic Intake & Integrity Agent",
        "Forensic Planning Agent",
        "Forensic Artifact Execution Agent",
        "Forensic Follow-up Planning Agent",
        "Forensic Evidence Correlation Agent",
        "Forensic Interpretation Agent",
        "Forensic Timeline Agent",
        "Forensic Reporting Agent",
    ]
    assert all(event["duration_ms"] >= 0 for event in completed)
    text = (reports / Path(result["report_path"]).name).read_text(encoding="utf-8")
    assert "Chain of custody and integrity" in text
    assert "## Proven Facts" in text
    assert "## Unresolved Anomalies" in text
    assert "MITRE ATT&CK" in text
    assert "Legal and evidentiary considerations" in text
    assert "automated results are" in text.lower()
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings[0] == "## Summary"
    assert "## Proven Facts" in headings
