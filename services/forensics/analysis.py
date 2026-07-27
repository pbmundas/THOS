"""Deterministic forensic evidence verification, triage, and correlation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

from services.detection import sigma_engine, sigmahq_engine
from services.detection import yara_engine
from services.detection.anomaly_scoring import score_rare_events
from services.enrichment import ioc_management
from services.siem import file_log_parser

FORENSIC_ROOT = Path(os.environ.get("FORENSIC_ROOT", "/data/log_sources/forensic"))
MANIFEST_NAME = "_thos_chain_of_custody.json"
MAX_FORENSIC_RECORDS = int(os.environ.get("FORENSIC_MAX_RECORDS", "50000"))
MAX_DOCUMENT_TEXT = int(os.environ.get("FORENSIC_MAX_DOCUMENT_TEXT", str(2 * 1024 * 1024)))

_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
}
_SUSPICIOUS = re.compile(
    r"\b(mimikatz|rundll32|regsvr32|certutil|powershell|encodedcommand|"
    r"credential dump|process injection|lsass|scheduled task|psexec|wscript|cscript)\b",
    re.IGNORECASE,
)


class ForensicIntegrityError(ValueError):
    pass


def _safe_case_dir(case_dir: str | Path) -> Path:
    root = FORENSIC_ROOT.resolve()
    candidate = Path(case_dir).resolve()
    if candidate == root or root not in candidate.parents:
        raise ForensicIntegrityError("forensic case path is outside the configured evidence root")
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
        if actual_size != int(item.get("size_bytes", -1)) or actual_hash != item.get("sha256"):
            raise ForensicIntegrityError(f"integrity verification failed: {stored_name}")
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
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            from pypdf import PdfReader
            return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        if suffix == ".docx":
            from docx import Document
            return "\n".join(paragraph.text for paragraph in Document(str(path)).paragraphs)
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
    except Exception as exc:  # noqa: BLE001
        entries.append({"error": str(exc)})
    return entries


def _tool_output(command: list[str], timeout: int = 120) -> dict:
    if not shutil.which(command[0]):
        return {"tool": command[0], "available": False, "output": ""}
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return {
            "tool": command[0], "available": True, "exit_code": result.returncode,
            "output": (result.stdout or result.stderr)[:200_000],
        }
    except Exception as exc:  # noqa: BLE001
        return {"tool": command[0], "available": True, "error": str(exc), "output": ""}


def _disk_image_analysis(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix in {".e01", ".ex01"}:
        return [_tool_output(["ewfinfo", str(path)])]
    if suffix in {".raw", ".dd", ".img", ".001"}:
        return [_tool_output(["mmls", str(path)])]
    if suffix == ".aff4":
        return [{"tool": "aff4", "available": False, "output": "", "note": "AFF4 decoder not installed"}]
    return []


def analyze_artifacts(verified: dict) -> dict:
    inventory, records, archives, disk_images, warnings = [], [], [], [], []
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
        archive_entries = _archive_inventory(path)
        if archive_entries:
            archives.append({"evidence_id": evidence["evidence_id"], "entries": archive_entries})
        disk_result = _disk_image_analysis(path)
        if disk_result:
            disk_images.append({"evidence_id": evidence["evidence_id"], "results": disk_result})
            if any(not result.get("available") for result in disk_result):
                warnings.append(
                    f"{evidence['evidence_id']}: deep disk-image decoder is unavailable; "
                    "hashes and bounded metadata remain verified."
                )
        parsed = file_log_parser.parse_file(str(path))
        text = _document_text(path)[:MAX_DOCUMENT_TEXT]
        if text:
            parsed.append({
                "timestamp": None, "host": None, "user": None,
                "event": f"document:{path.suffix.lower()}",
                "src_ip": None, "dst_ip": None, "detail": text,
                "source_file": evidence["original_name"], "source_type": "document",
            })
        for record in parsed:
            if len(records) >= MAX_FORENSIC_RECORDS:
                warnings.append(f"record cap reached at {MAX_FORENSIC_RECORDS}")
                break
            record = dict(record)
            record["_evidence_id"] = evidence["evidence_id"]
            record["_record_ref"] = f"{evidence['evidence_id']}:{len(records)}"
            records.append(record)
    return {
        "inventory": inventory,
        "records": records,
        "archives": archives,
        "disk_images": disk_images,
        "warnings": sorted(set(warnings)),
    }


def correlate_evidence(triage: dict) -> dict:
    records = triage.get("records", [])
    sigmahq = sigmahq_engine.evaluate_all(records)
    local_sigma = sigma_engine.evaluate_all(records)
    matched_indices = sorted(
        set(sigmahq.get("matched_record_indices", []))
        | set(local_sigma.get("matched_record_indices", []))
    )
    indicators: dict[str, set[str]] = {name: set() for name in _IOC_PATTERNS}
    indicator_refs: dict[str, set[str]] = {}
    suspicious = []
    for index, record in enumerate(records):
        text = " ".join(str(value) for value in record.values() if value)
        for name, pattern in _IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).rstrip(".,;)]}").lower()
                indicators[name].add(value)
                indicator_refs.setdefault(value, set()).add(
                    str(record.get("_record_ref", index))
                )
        if _SUSPICIOUS.search(text):
            suspicious.append({
                "ref": record.get("_record_ref", str(index)),
                "event": record.get("event"),
                "source_file": record.get("source_file"),
                "excerpt": str(record.get("detail", ""))[:500],
                "basis": "matched a review keyword; not a final maliciousness verdict",
            })
    yara_scan = yara_engine.scan_paths([
        item["path"] for item in triage.get("inventory", []) if item.get("path")
    ])
    blocklist = ioc_management.load_blocklist().get("indicators", {})
    network_entries = []
    for value, metadata in blocklist.items():
        if not isinstance(metadata, dict) or metadata.get("type") != "network":
            continue
        try:
            network_entries.append((ipaddress.ip_network(value, strict=False), value, metadata))
        except ValueError:
            continue
        if len(network_entries) >= 10_000:
            break
    ioc_matches = []
    for indicator_type, values in indicators.items():
        for value in values:
            metadata = blocklist.get(value)
            matched_value = value
            if not isinstance(metadata, dict) and indicator_type == "ipv4":
                try:
                    address = ipaddress.ip_address(value)
                    network_match = next(
                        ((network, network_value, item) for network, network_value, item in network_entries if address in network),
                        None,
                    )
                except ValueError:
                    network_match = None
                if network_match:
                    _, matched_value, metadata = network_match
            if not isinstance(metadata, dict):
                continue
            ioc_matches.append({
                "indicator": value,
                "matched_indicator": matched_value,
                "type": indicator_type,
                "category": metadata.get("category", "uncategorized"),
                "severity": metadata.get("severity", "medium"),
                "confidence": metadata.get("confidence", "medium"),
                "sources": metadata.get("sources", []),
                "last_seen": metadata.get("last_seen_by_thos", ""),
                "evidence_refs": sorted(indicator_refs.get(value, set()))[:50],
            })
    rule_by_ref: dict[str, list[str]] = {}
    for rule in sigmahq.get("rule_matches", []) + local_sigma.get("rule_matches", []):
        title = str(rule.get("title") or rule.get("rule_id") or "Sigma rule")
        for index in rule.get("matched_indices", []):
            if isinstance(index, int) and 0 <= index < len(records):
                ref = str(records[index].get("_record_ref", index))
                rule_by_ref.setdefault(ref, []).append(title)
    suspicious_refs = {str(item["ref"]): item for item in suspicious}
    activity = []
    for index in matched_indices:
        if not 0 <= index < len(records):
            continue
        record = records[index]
        ref = str(record.get("_record_ref", index))
        keyword_hit = suspicious_refs.get(ref)
        rules = sorted(set(rule_by_ref.get(ref, [])))
        classification = "malicious" if keyword_hit and len(rules) >= 2 else "suspicious"
        activity.append({
            "ref": ref,
            "classification": classification,
            "confidence": "high" if classification == "malicious" else "medium",
            "timestamp": record.get("timestamp"),
            "host": record.get("host"),
            "user": record.get("user"),
            "event": record.get("event"),
            "source_file": record.get("source_file"),
            "basis": (
                f"corroborated by {len(rules)} Sigma rule(s) and review behavior"
                if classification == "malicious"
                else f"matched Sigma rule(s): {', '.join(rules[:5])}"
            ),
            "sigma_rules": rules[:20],
            "excerpt": str(record.get("detail", ""))[:500],
        })
    known_refs = {item["ref"] for item in activity}
    for item in suspicious:
        if str(item["ref"]) not in known_refs:
            activity.append({
                **item,
                "classification": "suspicious",
                "confidence": "low",
            })
    for result in yara_scan.get("results", []):
        if not result.get("matches"):
            continue
        evidence = next(
            (item for item in triage.get("inventory", []) if item.get("path") == result.get("path")),
            {},
        )
        for match in result["matches"]:
            severity = str((match.get("meta") or {}).get("severity") or "medium").lower()
            activity.append({
                "ref": str(evidence.get("evidence_id") or result.get("sha256")),
                "classification": "malicious" if severity in {"critical", "high"} else "suspicious",
                "confidence": "high" if severity in {"critical", "high"} else "medium",
                "timestamp": None,
                "host": None,
                "user": None,
                "event": "yara_match",
                "source_file": evidence.get("original_name") or result.get("path"),
                "basis": f"YARA rule {match.get('rule_id')} matched file SHA-256 {result.get('sha256')}",
                "yara_rule": match.get("rule_id"),
                "excerpt": json.dumps(match.get("strings", [])[:10], default=str)[:500],
            })
    for match in ioc_matches:
        for reference in match.get("evidence_refs", [])[:20] or ["unscoped"]:
            activity.append({
                "ref": reference,
                "classification": "suspicious",
                "confidence": match.get("confidence", "medium"),
                "timestamp": None,
                "host": None,
                "user": None,
                "event": "threat_intelligence_match",
                "source_file": None,
                "basis": (
                    f"{match['indicator']} matched {match['matched_indicator']} in "
                    f"{len(match.get('sources', []))} managed IOC source(s)"
                ),
                "ioc": match["indicator"],
                "excerpt": (
                    f"Category={match.get('category')}; severity={match.get('severity')}; "
                    f"last_seen={match.get('last_seen')}"
                ),
            })
    sigma_matches = sigmahq.get("rule_matches", []) + local_sigma.get("rule_matches", [])
    attack_techniques = sorted({
        str(tag).split(".", 1)[1].upper()
        for rule in sigma_matches
        for tag in rule.get("tags", [])
        if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", str(tag), re.IGNORECASE)
    })
    return {
        "records_analyzed": len(records),
        "event_histogram": dict(Counter(str(item.get("event") or "unknown") for item in records).most_common(100)),
        "indicators": {name: sorted(values)[:500] for name, values in indicators.items()},
        "suspicious_observations": suspicious[:500],
        "sigmahq_rules_evaluated": sigmahq.get("rules_evaluated", 0),
        "sigmahq_rule_matches": sigmahq.get("rule_matches", [])[:200],
        "local_sigma_rules_evaluated": local_sigma.get("rules_evaluated", 0),
        "local_sigma_rule_matches": local_sigma.get("rule_matches", [])[:200],
        "sigma_matched_record_refs": [
            records[index].get("_record_ref", str(index))
            for index in matched_indices if 0 <= index < len(records)
        ],
        "anomaly_scores": score_rare_events(records)[:500],
        "yara_scan": yara_scan,
        "ioc_matches": ioc_matches[:1_000],
        "attack_techniques": attack_techniques,
        "activity_assessments": activity[:1_000],
    }


def build_timeline(triage: dict, correlation: dict | None = None) -> list[dict]:
    assessments = {
        str(item.get("ref")): item
        for item in (correlation or {}).get("activity_assessments", [])
    }
    timeline = []
    for record in triage.get("records", []):
        timestamp = record.get("timestamp")
        if not timestamp:
            continue
        reference = str(record.get("_record_ref") or "")
        assessment = assessments.get(reference, {})
        timeline.append({
            "timestamp": str(timestamp),
            "evidence_ref": record.get("_record_ref"),
            "host": record.get("host"),
            "user": record.get("user"),
            "event": record.get("event"),
            "source_file": record.get("source_file"),
            "detail": str(record.get("detail", ""))[:500],
            "classification": assessment.get("classification", "unclassified"),
            "confidence": assessment.get("confidence", ""),
            "activity_basis": assessment.get("basis", ""),
        })
    return sorted(timeline, key=lambda item: item["timestamp"])[:10_000]
