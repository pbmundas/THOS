"""Deterministic IOC source acquisition, normalization, and local persistence."""
from __future__ import annotations

from datetime import datetime, timezone
import csv
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import threading
from urllib.parse import urlparse

import httpx

THREAT_INTEL_ROOT = Path(os.environ.get("THOS_THREAT_INTEL_ROOT", "/data/threat_intel"))
BLOCKLIST_PATH = Path(os.environ.get("THOS_IOC_BLOCKLIST_PATH", str(THREAT_INTEL_ROOT / "blocklist.json")))
LOCAL_SOURCE_ROOT = Path(os.environ.get("THOS_IOC_LOCAL_SOURCE_ROOT", "/data/ioc_sources"))
MAX_SOURCE_BYTES = int(os.environ.get("THOS_IOC_MAX_SOURCE_BYTES", str(100 * 1024 * 1024)))
ALLOW_PRIVATE_FETCH = os.environ.get("THOS_IOC_ALLOW_PRIVATE_FETCH", "0").lower() in {"1", "true", "yes"}
_write_lock = threading.Lock()

_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,63}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.IGNORECASE),
}


class IOCSourceError(ValueError):
    pass


def _flatten_json(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _flatten_json(item)
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_json(item)
    elif value is not None:
        yield str(value)


def _payload_text(content: bytes, filename: str) -> str:
    decoded = content.decode("utf-8-sig", errors="replace")
    suffix = Path(filename).suffix.lower()
    if suffix in {".json", ".stix", ".stix2"}:
        try:
            return "\n".join(_flatten_json(json.loads(decoded)))
        except json.JSONDecodeError:
            return decoded
    if suffix in {".csv", ".tsv"}:
        try:
            delimiter = "\t" if suffix == ".tsv" else ","
            return "\n".join(
                str(cell)
                for row in csv.reader(io.StringIO(decoded), delimiter=delimiter)
                for cell in row
            )
        except csv.Error:
            return decoded
    return decoded


def extract_indicators(content: bytes, filename: str = "source") -> dict[str, set[str]]:
    text = _payload_text(content, filename)
    found = {kind: set() for kind in _PATTERNS}
    for kind, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,;)]}").lower()
            if kind in {"ipv4", "ipv6"}:
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    continue
            found[kind].add(value)
    # URLs contain domains; retaining both is useful for SIEM correlation.
    return found


def _validate_remote_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise IOCSourceError("IOC source URL must be an unauthenticated HTTP(S) URL")
    if parsed.port not in {None, 80, 443}:
        raise IOCSourceError("IOC source URL must use port 80 or 443")
    if ALLOW_PRIVATE_FETCH:
        return
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        }
    except (socket.gaierror, ValueError) as exc:
        raise IOCSourceError(f"IOC source hostname could not be resolved: {exc}") from exc
    if any(
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved
        for address in addresses
    ):
        raise IOCSourceError("IOC source URL resolves to a non-public address")


async def _fetch_remote(url: str) -> tuple[bytes, str, str]:
    _validate_remote_url(url)
    async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15), follow_redirects=False) as client:
        async with client.stream("GET", url, headers={"User-Agent": "THOS-IOC-Agent/1.0"}) as response:
            response.raise_for_status()
            declared = int(response.headers.get("content-length") or 0)
            if declared > MAX_SOURCE_BYTES:
                raise IOCSourceError("IOC source exceeds the configured size limit")
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    raise IOCSourceError("IOC source exceeds the configured size limit")
                chunks.append(chunk)
    name = Path(urlparse(url).path).name or "source.dat"
    return b"".join(chunks), name, response.headers.get("content-type", "application/octet-stream")


def _read_local(location: str) -> tuple[bytes, str, str]:
    root = LOCAL_SOURCE_ROOT.resolve()
    path = Path(location).resolve()
    if path != root and root not in path.parents:
        raise IOCSourceError("local IOC source is outside the configured source root")
    if not path.is_file():
        raise IOCSourceError("local IOC source file does not exist")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise IOCSourceError("IOC source exceeds the configured size limit")
    return path.read_bytes(), path.name, "application/octet-stream"


def _merge_blocklist(source: dict, indicators: dict[str, set[str]], fetched_at: str) -> int:
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        try:
            existing = json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {"indicators": {}}
        entries = existing.setdefault("indicators", {})
        count = 0
        for indicator_type, values in indicators.items():
            for value in sorted(values):
                prior = entries.get(value, {}) if isinstance(entries.get(value), dict) else {}
                sources = {
                    str(item) for item in prior.get("sources", [])
                    if str(item).strip()
                }
                sources.add(str(source["id"]))
                entries[value] = {
                    **prior,
                    "type": indicator_type,
                    "sources": sorted(sources),
                    "source_name": source.get("name") or source["id"],
                    "confidence": source.get("confidence", "medium"),
                    "first_seen_by_thos": prior.get("first_seen_by_thos") or fetched_at,
                    "last_seen_by_thos": fetched_at,
                }
                count += 1
        existing["updated_at"] = fetched_at
        existing["indicator_count"] = len(entries)
        temp = BLOCKLIST_PATH.with_suffix(".tmp")
        temp.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(BLOCKLIST_PATH)
    return count


async def refresh_source(source: dict) -> dict:
    location = str(source.get("location") or "").strip()
    if source.get("kind") == "local":
        content, filename, content_type = _read_local(location)
    else:
        content, filename, content_type = await _fetch_remote(location)
    fetched_at = datetime.now(timezone.utc).isoformat()
    source_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(source.get("id", "source")))[:80]
    archive_dir = (THREAT_INTEL_ROOT / "sources" / source_id).resolve()
    if THREAT_INTEL_ROOT.resolve() not in archive_dir.parents:
        raise IOCSourceError("invalid IOC source archive path")
    archive_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:160] or "source.dat"
    raw_path = archive_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{safe_name}"
    raw_path.write_bytes(content)
    indicators = extract_indicators(content, filename)
    extracted = _merge_blocklist(source, indicators, fetched_at)
    return {
        "source_id": source["id"],
        "fetched_at": fetched_at,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_type": content_type,
        "raw_path": str(raw_path),
        "extracted_count": extracted,
        "unique_by_type": {kind: len(values) for kind, values in indicators.items()},
    }
