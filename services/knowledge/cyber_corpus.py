"""Governed cybersecurity corpus ingestion with provenance on every chunk."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import glob
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request

import yaml


COLLECTION_NAME = "cyber_domain_kb"
CHUNK_WORDS = 360
CHUNK_OVERLAP = 45
ALLOWED_TRUST_TIERS = {"primary", "community-reviewed", "internal-licensed"}
PROHIBITED_LICENSES = {"", "unknown", "unknown-license", "proprietary-unlicensed"}
ALLOWED_REMOTE_HOSTS = {
    "raw.githubusercontent.com",
    "www.cisa.gov",
    "nvlpubs.nist.gov",
}
_INSTRUCTION_MARKERS = re.compile(
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?|"
    r"(?:system|assistant)\s*:|you\s+are\s+now\s+", re.IGNORECASE,
)
_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|password|secret)\b\s*[:=]\s*([^\s,;]{6,})"
)


class CorpusPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    enabled: bool
    required: bool
    kind: str
    location: str
    publisher: str
    license: str
    license_url: str
    trust_tier: str
    domains: tuple[str, ...]
    refresh_days: int
    max_bytes: int = 25_000_000
    max_files: int = 5_000
    fallback_location: str = ""


def load_manifest(path: str | Path) -> list[Source]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise CorpusPolicyError("unsupported cybersecurity source manifest schema")
    sources = []
    seen = set()
    for raw in payload.get("sources", []):
        source = Source(
            id=str(raw.get("id", "")).strip(),
            title=str(raw.get("title", "")).strip(),
            enabled=bool(raw.get("enabled")),
            required=bool(raw.get("required")),
            kind=str(raw.get("kind", "")).strip(),
            location=str(raw.get("location", "")).strip(),
            fallback_location=str(raw.get("fallback_location", "")).strip(),
            publisher=str(raw.get("publisher", "")).strip(),
            license=str(raw.get("license", "")).strip(),
            license_url=str(raw.get("license_url", "")).strip(),
            trust_tier=str(raw.get("trust_tier", "")).strip(),
            domains=tuple(str(item) for item in raw.get("domains", []) if str(item).strip()),
            refresh_days=max(0, int(raw.get("refresh_days", 30))),
            max_bytes=max(1, int(raw.get("max_bytes", 25_000_000))),
            max_files=max(1, int(raw.get("max_files", 5_000))),
        )
        validate_source(source)
        if source.id in seen:
            raise CorpusPolicyError(f"duplicate source id: {source.id}")
        seen.add(source.id)
        sources.append(source)
    return sources


def validate_source(source: Source) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_]{2,80}", source.id):
        raise CorpusPolicyError(f"invalid source id: {source.id!r}")
    if source.trust_tier not in ALLOWED_TRUST_TIERS:
        raise CorpusPolicyError(f"{source.id}: unsupported trust tier {source.trust_tier!r}")
    if source.license.lower() in PROHIBITED_LICENSES:
        raise CorpusPolicyError(f"{source.id}: license is missing or prohibited")
    if source.license == "PROPRIETARY-LICENSE-REQUIRED" and source.enabled:
        raise CorpusPolicyError(
            f"{source.id}: proprietary material cannot be enabled until its manifest "
            "entry names the organization-approved license"
        )
    if source.kind not in {"json", "pdf", "text", "local_glob"}:
        raise CorpusPolicyError(f"{source.id}: unsupported source kind {source.kind!r}")
    if not source.domains:
        raise CorpusPolicyError(f"{source.id}: at least one curriculum domain is required")
    if source.kind != "local_glob":
        parsed = urllib.parse.urlparse(source.location)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_REMOTE_HOSTS:
            raise CorpusPolicyError(f"{source.id}: remote host is not allowlisted")


def _download(source: Source) -> bytes:
    request = urllib.request.Request(
        source.location,
        headers={"User-Agent": "THOS-Cyber-Corpus/1.0 (+on-prem security knowledge ingestion)"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - host allowlist above
        length = int(response.headers.get("Content-Length") or 0)
        if length and length > source.max_bytes:
            raise CorpusPolicyError(f"{source.id}: remote object exceeds max_bytes")
        data = response.read(source.max_bytes + 1)
    if len(data) > source.max_bytes:
        raise CorpusPolicyError(f"{source.id}: downloaded object exceeds max_bytes")
    return data


def _clean_text(value: object) -> str:
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    text = _SECRET.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    return re.sub(r"\s+", " ", text).strip()


def _json_documents(source: Source, data: bytes) -> list[dict]:
    payload = json.loads(data.decode("utf-8"))
    is_stix_bundle = isinstance(payload, dict) and isinstance(payload.get("objects"), list)
    if is_stix_bundle:
        items = payload["objects"]
    elif isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        items = payload["vulnerabilities"]
    elif isinstance(payload, list):
        items = payload
    else:
        items = [payload]
    documents = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        # ATT&CK bundles also contain thousands of relationships, identities,
        # and marking objects. Techniques are the high-value reference unit
        # for this bounded corpus; excluding graph plumbing cuts embedding
        # time and noise substantially.
        if is_stix_bundle and (
            item.get("type") != "attack-pattern"
            or item.get("revoked") is True
            or item.get("x_mitre_deprecated") is True
        ):
            continue
        external_id = ""
        references = item.get("external_references") or []
        if references and isinstance(references, list) and isinstance(references[0], dict):
            external_id = str(references[0].get("external_id") or "")
        item_id = str(
            item.get("cveID") or external_id or item.get("id") or f"record-{index}"
        )
        title = str(
            item.get("name") or item.get("vulnerabilityName") or item.get("title") or item_id
        )
        preferred = [
            item.get("description"), item.get("shortDescription"), item.get("requiredAction"),
            item.get("x_mitre_detection"), item.get("x_mitre_version"),
        ]
        body = " ".join(_clean_text(value) for value in preferred if value)
        if not body:
            body = _clean_text(json.dumps(item, ensure_ascii=False, default=str))
        documents.append({"record_id": item_id, "title": title, "text": f"{title}. {body}"})
    return documents


def _pdf_documents(source: Source, data: bytes) -> list[dict]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    documents = []
    for index, page in enumerate(reader.pages):
        text = _clean_text(page.extract_text() or "")
        if text:
            documents.append({
                "record_id": f"page-{index + 1}",
                "title": f"{source.title}, page {index + 1}",
                "text": text,
            })
    return documents


def _sigma_document(path: str) -> dict | None:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(raw, dict) or not raw.get("title"):
        return None
    rule_id = str(raw.get("id") or Path(path).stem)
    fields = {
        "title": raw.get("title"), "status": raw.get("status"),
        "description": raw.get("description"), "logsource": raw.get("logsource"),
        "detection": raw.get("detection"), "falsepositives": raw.get("falsepositives"),
        "level": raw.get("level"), "tags": raw.get("tags"), "references": raw.get("references"),
    }
    return {
        "record_id": rule_id,
        "title": str(raw["title"]),
        "text": _clean_text(yaml.safe_dump(fields, sort_keys=False)),
    }


def _local_documents(source: Source) -> list[dict]:
    pattern = source.location
    files = glob.glob(pattern, recursive=True)
    if not files and source.fallback_location:
        files = glob.glob(source.fallback_location, recursive=True)
    documents = []
    for path in sorted(files)[:source.max_files]:
        if not Path(path).is_file():
            continue
        if Path(path).suffix.lower() in {".yml", ".yaml"}:
            document = _sigma_document(path)
        else:
            try:
                text = _clean_text(Path(path).read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            document = {
                "record_id": Path(path).name,
                "title": Path(path).name,
                "text": text,
            } if text else None
        if document:
            documents.append(document)
    return documents


def source_documents(source: Source) -> tuple[list[dict], str]:
    if source.kind == "local_glob":
        documents = _local_documents(source)
        digest = hashlib.sha256(
            "".join(item["record_id"] + item["text"] for item in documents).encode("utf-8")
        ).hexdigest()
        return documents, digest
    data = _download(source)
    digest = hashlib.sha256(data).hexdigest()
    if source.kind == "json":
        return _json_documents(source, data), digest
    if source.kind == "pdf":
        return _pdf_documents(source, data), digest
    return [{"record_id": "document", "title": source.title, "text": _clean_text(data.decode("utf-8", errors="replace"))}], digest


def _chunks(text: str) -> list[str]:
    words = text.split()
    chunks = []
    step = max(1, CHUNK_WORDS - CHUNK_OVERLAP)
    for start in range(0, len(words), step):
        chunk = " ".join(words[start:start + CHUNK_WORDS]).strip()
        if chunk:
            chunks.append(chunk)
        if start + CHUNK_WORDS >= len(words):
            break
    return chunks


def ingest_source(collection, source: Source) -> dict:
    documents, source_hash = source_documents(source)
    retrieved_at = datetime.now(timezone.utc).isoformat()
    try:
        collection.delete(where={"source_id": source.id})
    except Exception:
        pass
    ids, chunks, metadata = [], [], []
    for document in documents:
        for chunk_index, chunk in enumerate(_chunks(document["text"])):
            citation_id = f"CYBER:{source.id}:{document['record_id']}:{chunk_index}"
            stable_id = hashlib.sha256(citation_id.encode("utf-8")).hexdigest()
            ids.append(stable_id)
            chunks.append(chunk)
            metadata.append({
                "citation_id": citation_id,
                "source_id": source.id,
                "source_title": source.title,
                "record_id": str(document["record_id"])[:300],
                "record_title": str(document["title"])[:500],
                "publisher": source.publisher,
                "license": source.license,
                "license_url": source.license_url,
                "trust_tier": source.trust_tier,
                "domains": ",".join(source.domains),
                "retrieved_at": retrieved_at,
                "source_hash": source_hash,
                "instruction_like_text": bool(_INSTRUCTION_MARKERS.search(chunk)),
            })
    if ids:
        batch_size = 128
        for start in range(0, len(ids), batch_size):
            collection.upsert(
                ids=ids[start:start + batch_size],
                documents=chunks[start:start + batch_size],
                metadatas=metadata[start:start + batch_size],
            )
    return {
        "source_id": source.id,
        "documents": len(documents),
        "chunks": len(ids),
        "source_hash": source_hash,
        "retrieved_at": retrieved_at,
    }


def ingest_manifest(collection, manifest_path: str | Path, source_ids: set[str] | None = None) -> dict:
    results, failures = [], []
    for source in load_manifest(manifest_path):
        if not source.enabled or (source_ids and source.id not in source_ids):
            continue
        try:
            results.append(ingest_source(collection, source))
        except Exception as exc:  # noqa: BLE001 - report per-source failures
            failures.append({"source_id": source.id, "required": source.required, "error": str(exc)})
    required_failures = [item for item in failures if item["required"]]
    return {
        "status": "failed" if required_failures else ("degraded" if failures else "passed"),
        "sources_ingested": len(results),
        "chunks_ingested": sum(item["chunks"] for item in results),
        "results": results,
        "failures": failures,
    }
