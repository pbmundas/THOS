"""Deterministic forensic evidence verification, triage, and correlation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

from services.detection import sigma_engine, sigmahq_engine
from services.detection.anomaly_scoring import score_rare_events
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
    suspicious = []
    for index, record in enumerate(records):
        text = " ".join(str(value) for value in record.values() if value)
        for name, pattern in _IOC_PATTERNS.items():
            indicators[name].update(match.group(0) for match in pattern.finditer(text))
        if _SUSPICIOUS.search(text):
            suspicious.append({
                "ref": record.get("_record_ref", str(index)),
                "event": record.get("event"),
                "source_file": record.get("source_file"),
                "excerpt": str(record.get("detail", ""))[:500],
                "basis": "matched a review keyword; not a final maliciousness verdict",
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
    }


def build_timeline(triage: dict) -> list[dict]:
    timeline = []
    for record in triage.get("records", []):
        timestamp = record.get("timestamp")
        if not timestamp:
            continue
        timeline.append({
            "timestamp": str(timestamp),
            "evidence_ref": record.get("_record_ref"),
            "host": record.get("host"),
            "user": record.get("user"),
            "event": record.get("event"),
            "source_file": record.get("source_file"),
            "detail": str(record.get("detail", ""))[:500],
        })
    return sorted(timeline, key=lambda item: item["timestamp"])[:10_000]
