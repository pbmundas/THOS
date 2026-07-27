"""Risk Analysis Agent.

Converts verifier-supported hunt-report findings and persisted scheduled
detections into a uniform, explainable risk register. The implementation is
deterministic so opening the Risks or Overview pages never consumes an LLM
worker or changes source evidence.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
from typing import Any


_SEVERITY_SCORE = {
    "critical": 92,
    "high": 80,
    "medium": 62,
    "low": 38,
    "informational": 20,
}


def _severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _report_title(markdown: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", markdown, flags=re.MULTILINE)
    return re.sub(r"[*_`]", "", match.group(1)).strip() if match else fallback


def _report_findings(markdown: str) -> list[str]:
    match = re.search(
        r"^###\s+.*Security Findings\s*$([\s\S]*?)(?=^###\s+|^##\s+|\Z)",
        markdown,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return []
    findings = []
    for line in match.group(1).splitlines():
        if not re.match(r"^\s*[-*]\s+", line):
            continue
        value = re.sub(r"^\s*[-*]\s+", "", line).strip()
        value = re.sub(r"^\[[^\]]+\]\s*", "", value).strip()
        if not value or "no findings" in value.lower():
            continue
        normalized = value.lower().strip()
        negative_prefixes = (
            "no evidence",
            "no indication",
            "no indicators",
            "no network",
            "no process",
            "no suspicious",
            "not observed",
            "not detected",
            "none observed",
            "absence of",
            "insufficient evidence",
            "the hypothesis is not supported",
            "the hypothesis was not supported",
        )
        if normalized.startswith(negative_prefixes):
            continue
        findings.append(value[:1600])
    return findings[:20]


def _entity_from_report(markdown: str, finding: str) -> dict[str, str]:
    network_finding = any(
        token in finding.lower()
        for token in ("network", "nmap", "scan", "connection", "remote", "ip ")
    )
    patterns = []
    if network_finding:
        patterns.append(("IP address", r'"src_ip"\s*:\s*"([^"]+)"'))
    patterns.extend((
        ("Host", r'"host"\s*:\s*"([^"]+)"'),
        ("User", r'"user"\s*:\s*"([^"]+)"'),
        ("IP address", r'"src_ip"\s*:\s*"([^"]+)"'),
        ("IP address", r'"dst_ip"\s*:\s*"([^"]+)"'),
    ))
    for entity_type, pattern in patterns:
        match = re.search(pattern, markdown)
        if match and match.group(1).strip() not in {"", "—", "-"}:
            return {"type": entity_type, "name": match.group(1).strip()[:240]}
    technique = re.search(r"MITRE ATT&CK.*?\|\s*([^|\n]+)", markdown)
    if technique:
        return {"type": "ATT&CK technique", "name": technique.group(1).strip()[:240]}
    return {"type": "Investigation", "name": "Environment-wide"}


def _entity_from_detection(detection: dict) -> dict[str, str]:
    events = detection.get("matched_events") or []
    candidates = (
        ("Host", "host"),
        ("User", "user"),
        ("IP address", "src_ip"),
        ("IP address", "dst_ip"),
    )
    for entity_type, key in candidates:
        counts: dict[str, int] = defaultdict(int)
        for event in events if isinstance(events, list) else []:
            if isinstance(event, dict) and event.get(key):
                counts[str(event[key]).strip()] += 1
        if counts:
            name = max(counts, key=counts.get)
            return {"type": entity_type, "name": name[:240]}
    return {
        "type": "Telemetry source",
        "name": str(detection.get("siem_type") or "Unknown source")[:240],
    }


def _finding_name(finding: str) -> str:
    name = re.split(r"\s*\((?:evidence|ref)\s*:", finding, maxsplit=1, flags=re.I)[0]
    name = re.sub(r"^(evidence of|observed|detected)\s+", "", name, flags=re.I)
    name = name.strip(" .:-")
    if not name:
        return "Verifier-supported hunt finding"
    return name[:110] + ("…" if len(name) > 110 else "")


def _risk_id(source_type: str, source_id: str, name: str, entity: str) -> str:
    material = f"{source_type}|{source_id}|{name.lower()}|{entity.lower()}"
    return "risk-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _report_risks(hunts: list[dict], reports_root: Path) -> list[dict]:
    risks: list[dict] = []
    for hunt in hunts:
        if hunt.get("status") != "completed":
            continue
        report_path = str(hunt.get("report_path") or "")
        if not report_path:
            continue
        candidate = reports_root / Path(report_path).name
        if not candidate.is_file():
            continue
        markdown = candidate.read_text(encoding="utf-8", errors="replace")
        verifier_passed = bool(re.search(
            r"Verifier[\s\S]{0,500}?(?:`passed`|Passed:)", markdown, flags=re.I
        ))
        if not verifier_passed:
            continue
        findings = _report_findings(markdown)
        report_title = _report_title(markdown, candidate.stem.replace("_", " "))
        for finding in findings:
            entity = _entity_from_report(markdown, finding)
            hard_evidence = "hard-evidence" in finding.lower() or "evidence:" in finding.lower()
            score = 78 if hard_evidence else 68
            if any(word in finding.lower() for word in ("malware", "ransomware", "credential", "nmap", "exploit")):
                score += 5
            if hunt.get("outcome", {}).get("reasoning_degraded"):
                score -= 8
            score = max(1, min(score, 100))
            name = _finding_name(finding)
            hypothesis = str(hunt.get("hypothesis_id") or "dynamic hypothesis")
            risks.append({
                "id": _risk_id("report", str(hunt.get("hunt_id")), name, entity["name"]),
                "name": name,
                "description": (
                    f"What: {finding} Why this is a risk: the finding was supported by "
                    f"persisted evidence and passed citation verification. How discovered: "
                    f"the Risk Analysis Agent reviewed hunt report {hypothesis} and its "
                    f"validated Security Findings section."
                ),
                "what": finding,
                "why": "Persisted hunt evidence supports potentially harmful or unauthorized behavior.",
                "discovery": f"Verifier-supported finding in {report_title}.",
                "entity": entity,
                "score": score,
                "severity": _severity(score),
                "identified_at": _timestamp(hunt.get("created_at")),
                "last_seen_at": _timestamp(hunt.get("updated_at") or hunt.get("created_at")),
                "source_type": "hunt_report",
                "source_label": report_title,
                "source_id": str(hunt.get("hunt_id") or ""),
                "report_filename": candidate.name,
                "detection_run_id": "",
                "evidence_count": 1,
                "status": "open",
            })
    return risks


def _detection_risks(detections: list[dict]) -> list[dict]:
    risks: list[dict] = []
    for detection in detections:
        matched = int(detection.get("events_matched") or 0)
        if matched <= 0:
            continue
        entity = _entity_from_detection(detection)
        level = str(detection.get("level") or "medium").lower()
        score = min(100, _SEVERITY_SCORE.get(level, 62) + min(8, matched // 2))
        title = str(detection.get("rule_title") or detection.get("rule_id") or "Detection")
        rule_id = str(detection.get("rule_id") or "unknown-rule")
        run_id = str(detection.get("run_id") or "")
        analysis = detection.get("analysis") or {}
        summary = str(analysis.get("summary") or f"{matched} matching events were recorded.")
        risks.append({
            "id": _risk_id("detection", run_id, title, entity["name"]),
            "name": title[:140],
            "description": (
                f"What: {title} affected {entity['type'].lower()} {entity['name']}. "
                f"Why this is a risk: the {level} detection rule matched {matched} event(s). "
                f"How discovered: the Risk Analysis Agent reviewed persisted scheduled "
                f"detection {rule_id}. {summary}"
            ),
            "what": f"{title} matched {matched} event(s).",
            "why": f"A {level} scheduled rule produced evidence on {entity['name']}.",
            "discovery": f"Scheduled detection {rule_id}; {summary}",
            "entity": entity,
            "score": score,
            "severity": _severity(score),
            "identified_at": _timestamp(detection.get("created_at")),
            "last_seen_at": _timestamp(
                analysis.get("last_event_at") or detection.get("created_at")
            ),
            "source_type": "detection",
            "source_label": f"{title} · {rule_id}",
            "source_id": rule_id,
            "report_filename": "",
            "detection_run_id": run_id,
            "evidence_count": matched,
            "status": "open",
        })
    return risks


def _consolidate(risks: list[dict]) -> list[dict]:
    consolidated: dict[tuple[str, str, str], dict] = {}
    for risk in risks:
        key = (
            risk["source_type"],
            risk["name"].lower(),
            risk["entity"]["name"].lower(),
        )
        current = consolidated.get(key)
        if current is None:
            consolidated[key] = dict(risk)
            continue
        current["identified_at"] = min(current["identified_at"], risk["identified_at"])
        current["last_seen_at"] = max(current["last_seen_at"], risk["last_seen_at"])
        current["evidence_count"] += risk["evidence_count"]
        current["score"] = min(100, max(current["score"], risk["score"]) + 2)
        current["severity"] = _severity(current["score"])
        if risk["last_seen_at"] >= current["last_seen_at"]:
            for field in ("source_label", "source_id", "report_filename", "detection_run_id"):
                current[field] = risk[field]
    return sorted(
        consolidated.values(),
        key=lambda item: (item["score"], item["last_seen_at"]),
        reverse=True,
    )


def analyze_actionable_risks(
    hunts: list[dict],
    detections: list[dict],
    reports_dir: str | Path,
    limit: int = 500,
    hours: int | None = None,
) -> dict:
    """Return a uniform actionable-risk register and executive summary."""
    risks = _consolidate([
        *_report_risks(hunts, Path(reports_dir)),
        *_detection_risks(detections),
    ])
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=max(1, min(int(hours), 24 * 365 * 10))
        )
        risks = [
            item for item in risks
            if datetime.fromisoformat(item["identified_at"]) >= cutoff
        ]
    risks = risks[:max(1, min(int(limit), 2000))]
    entities = {
        f"{item['entity']['type']}:{item['entity']['name']}" for item in risks
    }
    summary = {
        "total": len(risks),
        "critical": sum(item["severity"] == "critical" for item in risks),
        "high": sum(item["severity"] == "high" for item in risks),
        "medium": sum(item["severity"] == "medium" for item in risks),
        "low": sum(item["severity"] == "low" for item in risks),
        "affected_entities": len(entities),
        "average_score": round(
            sum(item["score"] for item in risks) / len(risks), 1
        ) if risks else 0,
        "report_findings": sum(item["source_type"] == "hunt_report" for item in risks),
        "detection_findings": sum(item["source_type"] == "detection" for item in risks),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent": {
            "id": "risk_analysis",
            "name": "Risk Analysis Agent",
            "mode": "deterministic evidence correlation",
        },
        "summary": summary,
        "items": risks,
    }
