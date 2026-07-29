"""Evidence-preserving forensic intake, tool execution, and fact correlation.

This module deliberately does not assign maliciousness. It verifies evidence,
executes a validated model-selected tool plan, and produces cited facts for the
Forensic Interpretation Agent.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tarfile
import zipfile

from services.enrichment import ioc_management
from services.forensics.tools import run_static_triage, tool_status
from services.siem import file_log_parser

FORENSIC_ROOT = Path(os.environ.get("FORENSIC_ROOT", "/data/log_sources/forensic"))
MANIFEST_NAME = "_thos_chain_of_custody.json"
MAX_FORENSIC_RECORDS = int(os.environ.get("FORENSIC_MAX_RECORDS", "50000"))
MAX_DOCUMENT_TEXT = int(
    os.environ.get("FORENSIC_MAX_DOCUMENT_TEXT", str(2 * 1024 * 1024))
)

# These patterns extract literal observables. They do not decide whether an
# observable is malicious.
_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
    ),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
}


class ForensicIntegrityError(ValueError):
    pass


def _safe_case_dir(case_dir: str | Path) -> Path:
    root = FORENSIC_ROOT.resolve()
    candidate = Path(case_dir).resolve()
    if candidate == root or root not in candidate.parents:
        raise ForensicIntegrityError(
            "forensic case path is outside the configured evidence root"
        )
    if not candidate.is_dir():
        raise ForensicIntegrityError("forensic case directory does not exist")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_evidence(case_dir: str | Path) -> dict:
    """Verify containment, declared size, and SHA-256 for every case artifact."""
    case_path = _safe_case_dir(case_dir)
    manifest_path = case_path / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ForensicIntegrityError("chain-of-custody manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verified = []
    for item in manifest.get("evidence", []):
        stored_name = Path(str(item.get("stored_name", ""))).name
        path = (case_path / stored_name).resolve()
        if path.parent != case_path or not path.is_file():
            raise ForensicIntegrityError(f"evidence file is missing: {stored_name}")
        actual_size = path.stat().st_size
        actual_hash = sha256_file(path)
        if (
            actual_size != int(item.get("size_bytes", -1))
            or actual_hash != item.get("sha256")
        ):
            raise ForensicIntegrityError(
                f"integrity verification failed: {stored_name}"
            )
        verified.append({
            **item,
            "path": str(path),
            "verified_sha256": actual_hash,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        })
    if not verified:
        raise ForensicIntegrityError("case contains no evidence files")
    return {**manifest, "case_dir": str(case_path), "evidence": verified}


def _document_text(path: Path) -> str:
    try:
        if path.suffix.lower() == ".pdf":
            from pypdf import PdfReader
            return "\n".join(
                page.extract_text() or "" for page in PdfReader(str(path)).pages
            )
        if path.suffix.lower() == ".docx":
            from docx import Document
            return "\n".join(
                paragraph.text for paragraph in Document(str(path)).paragraphs
            )
    except Exception:
        return ""
    return ""


def _archive_inventory(path: Path) -> list[dict]:
    entries = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for item in archive.infolist()[:5000]:
                    entries.append({
                        "name": item.filename,
                        "size": item.file_size,
                        "compressed_size": item.compress_size,
                        "crc32": f"{item.CRC:08x}",
                        "encrypted": bool(item.flag_bits & 0x1),
                    })
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                for item in archive.getmembers()[:5000]:
                    entries.append({
                        "name": item.name,
                        "size": item.size,
                        "type": "directory" if item.isdir() else "file",
                    })
    except Exception as exc:
        entries.append({"error": str(exc)})
    return entries


def analyze_artifacts(verified: dict, tool_plan: dict | None = None) -> dict:
    """Execute the validated per-artifact plan and parse supported evidence."""
    inventory, records, archives, disk_images, warnings, static_analysis = (
        [], [], [], [], [], []
    )
    derived_dir = Path(verified["case_dir"]) / "_thos_derived"
    derived_dir.mkdir(mode=0o750, exist_ok=True)
    plan_by_evidence = {
        str(item.get("evidence_id")): list(item.get("tools") or [])
        for item in (tool_plan or {}).get("artifacts") or []
        if isinstance(item, dict)
    }
    for evidence in verified["evidence"]:
        path = Path(evidence["path"])
        with path.open("rb") as handle:
            magic = handle.read(16).hex()
        item = {
            "evidence_id": evidence["evidence_id"],
            "original_name": evidence["original_name"],
            "stored_name": evidence["stored_name"],
            "size_bytes": evidence["size_bytes"],
            "sha256": evidence["sha256"],
            "extension": path.suffix.lower() or "(none)",
            "magic_hex": magic,
            "path": str(path),
        }
        inventory.append(item)
        result = run_static_triage(
            path,
            sha256=str(evidence["sha256"]),
            artifact_type=str(evidence.get("artifact_type") or "evidence"),
            derived_dir=derived_dir,
            tool_plan=plan_by_evidence.get(str(evidence["evidence_id"]), []),
        )
        result["evidence_id"] = evidence["evidence_id"]
        static_analysis.append(result)
        for tool_result in result.get("results", []):
            if tool_result.get("status") in {
                "failed", "timed_out", "invalid_plan", "adapter_unavailable"
            }:
                warnings.append(
                    f"{evidence['evidence_id']}: "
                    f"{tool_result.get('tool_id')} {tool_result.get('status')}: "
                    f"{tool_result.get('error') or tool_result.get('note') or 'review output'}"
                )
        archive_entries = _archive_inventory(path)
        if archive_entries:
            archives.append({
                "evidence_id": evidence["evidence_id"],
                "entries": archive_entries,
            })
        disk_results = [
            tool_result
            for tool_result in result.get("results", [])
            if tool_result.get("tool_id") in {
                "ewf", "sleuthkit"
            }
        ]
        if disk_results:
            disk_images.append({
                "evidence_id": evidence["evidence_id"],
                "results": disk_results,
            })
        parsed = file_log_parser.parse_file(str(path))
        text = _document_text(path)[:MAX_DOCUMENT_TEXT]
        if text:
            parsed.append({
                "timestamp": None,
                "host": None,
                "user": None,
                "event": f"document:{path.suffix.lower()}",
                "src_ip": None,
                "dst_ip": None,
                "detail": text,
                "source_file": evidence["original_name"],
                "source_type": "document",
            })
        for record in parsed:
            if len(records) >= MAX_FORENSIC_RECORDS:
                warnings.append(
                    f"record safety cap reached at {MAX_FORENSIC_RECORDS}"
                )
                break
            record = dict(record)
            record["_evidence_id"] = evidence["evidence_id"]
            record["_record_ref"] = (
                f"{evidence['evidence_id']}:{len(records)}"
            )
            records.append(record)
    return {
        "inventory": inventory,
        "records": records,
        "archives": archives,
        "disk_images": disk_images,
        "static_analysis": static_analysis,
        "forensic_tools": tool_status(),
        "tool_plan": tool_plan or {},
        "warnings": sorted(set(warnings)),
    }


def apply_followup_tool_plan(
    triage: dict,
    verified: dict,
    tool_plan: dict,
) -> dict:
    """Execute a second validated agent plan and append its observations."""
    updated = dict(triage)
    static_analysis = list(triage.get("static_analysis") or [])
    derived_dir = Path(verified["case_dir"]) / "_thos_derived"
    evidence_by_id = {
        str(item.get("evidence_id")): item
        for item in verified.get("evidence") or []
    }
    for artifact in tool_plan.get("artifacts") or []:
        if not isinstance(artifact, dict) or not artifact.get("tools"):
            continue
        evidence_id = str(artifact.get("evidence_id") or "")
        evidence = evidence_by_id.get(evidence_id)
        if not evidence:
            continue
        result = run_static_triage(
            evidence["path"],
            sha256=str(evidence["sha256"]),
            artifact_type=str(evidence.get("artifact_type") or "evidence"),
            derived_dir=derived_dir,
            tool_plan=list(artifact.get("tools") or []),
        )
        result["evidence_id"] = evidence_id
        static_analysis.append(result)
    updated["static_analysis"] = static_analysis
    updated["followup_tool_plan"] = tool_plan
    return updated


def _global_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _extract_indicators(records: list[dict]) -> tuple[dict, dict]:
    indicators: dict[str, set[str]] = {
        name: set() for name in _IOC_PATTERNS
    }
    refs: dict[str, set[str]] = {}
    for index, record in enumerate(records):
        text = " ".join(str(value) for value in record.values() if value)
        for name, pattern in _IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).rstrip(".,;)]}").lower()
                if name == "ipv4":
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                indicators[name].add(value)
                refs.setdefault(value, set()).add(
                    str(record.get("_record_ref", index))
                )
    return indicators, refs


def _ioc_matches(indicators: dict, refs: dict) -> list[dict]:
    blocklist = ioc_management.load_blocklist().get("indicators", {})
    networks = []
    for value, metadata in blocklist.items():
        if not isinstance(metadata, dict) or metadata.get("type") != "network":
            continue
        try:
            networks.append(
                (ipaddress.ip_network(value, strict=False), value, metadata)
            )
        except ValueError:
            continue
        if len(networks) >= 10_000:
            break
    matches = []
    for indicator_type, values in indicators.items():
        for value in values:
            metadata = blocklist.get(value)
            matched_value = value
            if (
                not isinstance(metadata, dict)
                and indicator_type in {"ipv4", "ipv6"}
                and _global_address(value)
            ):
                address = ipaddress.ip_address(value)
                network_match = next(
                    (
                        (network_value, item)
                        for network, network_value, item in networks
                        if address.version == network.version and address in network
                    ),
                    None,
                )
                if network_match:
                    matched_value, metadata = network_match
            if not isinstance(metadata, dict):
                continue
            matches.append({
                "indicator": value,
                "matched_indicator": matched_value,
                "type": indicator_type,
                "category": metadata.get("category", "uncategorized"),
                "severity": metadata.get("severity", "medium"),
                "confidence": metadata.get("confidence", "medium"),
                "sources": metadata.get("sources", []),
                "last_seen": metadata.get("last_seen_by_thos", ""),
                "evidence_refs": sorted(refs.get(value, set()))[:50],
            })
    return matches


def _tool_facts(triage: dict) -> list[dict]:
    facts = []
    for artifact in triage.get("static_analysis") or []:
        evidence_id = str(
            artifact.get("evidence_id") or artifact.get("sha256") or ""
        )
        for index, result in enumerate(artifact.get("results") or []):
            if not isinstance(result, dict):
                continue
            status = str(result.get("status") or "")
            observable = any(
                result.get(field) not in (None, "", [], {})
                for field in ("output", "data", "error", "note")
            )
            if status not in {"completed", "failed", "timed_out"} and not observable:
                continue
            facts.append({
                "fact_id": f"tool:{evidence_id}:{index}",
                "fact_type": "forensic_tool_result",
                "evidence_refs": [evidence_id],
                "tool_id": result.get("tool_id"),
                "status": status,
                "exit_code": result.get("exit_code"),
                "output": str(result.get("output") or "")[:4000],
                "data": result.get("data"),
                "error": str(result.get("error") or "")[:1000],
                "note": str(result.get("note") or "")[:1000],
            })
    return facts


def correlate_evidence(triage: dict) -> dict:
    """Produce literal, cited observations without assigning a verdict."""
    records = list(triage.get("records") or [])
    indicators, indicator_refs = _extract_indicators(records)
    ioc_matches = _ioc_matches(indicators, indicator_refs)
    facts: list[dict] = []
    yara_results = []
    for artifact in triage.get("static_analysis") or []:
        evidence_id = str(
            artifact.get("evidence_id") or artifact.get("sha256") or ""
        )
        for result in artifact.get("results") or []:
            if (
                result.get("tool_id") != "yara"
                or not isinstance(result.get("data"), dict)
            ):
                continue
            yara_results.append(result["data"])
            for scan_index, scan in enumerate(
                result["data"].get("results") or []
            ):
                for match_index, match in enumerate(
                    scan.get("matches") or []
                ):
                    facts.append({
                        "fact_id": (
                            f"yara:{evidence_id}:{scan_index}:{match_index}"
                        ),
                        "fact_type": "yara_rule_match",
                        "evidence_refs": [evidence_id],
                        "rule_id": match.get("rule_id"),
                        "namespace": match.get("namespace"),
                        "metadata": match.get("meta") or {},
                        "strings": (match.get("strings") or [])[:50],
                        "sha256": scan.get("sha256"),
                    })
    for index, match in enumerate(ioc_matches):
        facts.append({
            "fact_id": f"ioc:{index}",
            "fact_type": "threat_intelligence_match",
            "evidence_refs": match.get("evidence_refs") or [],
            **match,
        })
    facts.extend(_tool_facts(triage))
    yara_scan = {
        "files_scanned": sum(
            int(item.get("files_scanned", 0) or 0)
            for item in yara_results
        ),
        "matched_files": sum(
            int(item.get("matched_files", 0) or 0)
            for item in yara_results
        ),
        "match_count": sum(
            int(item.get("match_count", 0) or 0)
            for item in yara_results
        ),
        "results": [
            result
            for item in yara_results
            for result in item.get("results") or []
        ][:1000],
        "execution_owner": "forensic_planner_model",
    }
    return {
        "records_analyzed": len(records),
        "event_histogram": dict(
            Counter(
                str(item.get("event") or "unknown") for item in records
            ).most_common(100)
        ),
        "indicators": {
            name: sorted(values)[:500] for name, values in indicators.items()
        },
        "detection_rules_evaluated": 0,
        "detection_rule_matches": [],
        "matched_record_refs": [],
        "yara_scan": yara_scan,
        "ioc_matches": ioc_matches[:1000],
        "attack_techniques": [],
        "attack_techniques_by_ref": {},
        "evidence_facts": facts[:3000],
        "activity_assessments": [],
        "interpretation_status": "pending_agent_interpretation",
    }


def build_timeline(
    triage: dict,
    correlation: dict | None = None,
) -> list[dict]:
    assessments_by_ref: dict[str, dict] = {}
    for assessment in (correlation or {}).get("activity_assessments") or []:
        for reference in assessment.get("evidence_refs") or [
            assessment.get("ref")
        ]:
            if reference:
                assessments_by_ref[str(reference)] = assessment
    attack_by_ref = (correlation or {}).get("attack_techniques_by_ref", {})
    timeline = []
    for record in triage.get("records", []):
        timestamp = record.get("timestamp")
        if not timestamp:
            continue
        reference = str(record.get("_record_ref") or "")
        assessment = assessments_by_ref.get(reference, {})
        timeline.append({
            "timestamp": str(timestamp),
            "evidence_ref": record.get("_record_ref"),
            "host": record.get("host"),
            "user": record.get("user"),
            "event": record.get("event"),
            "source_file": record.get("source_file"),
            "detail": str(record.get("detail", ""))[:500],
            "classification": assessment.get("classification", "unassessed"),
            "confidence": assessment.get("confidence", ""),
            "activity_basis": assessment.get("basis", ""),
            "mitre_techniques": list(
                attack_by_ref.get(reference, [])
            )[:20],
        })
    return sorted(timeline, key=lambda item: item["timestamp"])[:10000]
