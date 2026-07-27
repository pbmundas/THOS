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
from urllib.parse import urljoin, urlparse

import httpx

THREAT_INTEL_ROOT = Path(os.environ.get("THOS_THREAT_INTEL_ROOT", "/data/threat_intel"))
BLOCKLIST_PATH = Path(os.environ.get("THOS_IOC_BLOCKLIST_PATH", str(THREAT_INTEL_ROOT / "blocklist.json")))
LOCAL_SOURCE_ROOT = Path(os.environ.get("THOS_IOC_LOCAL_SOURCE_ROOT", "/data/ioc_sources"))
MAX_SOURCE_BYTES = int(os.environ.get("THOS_IOC_MAX_SOURCE_BYTES", str(20 * 1024 * 1024)))
MAX_INDICATORS_PER_SOURCE = int(os.environ.get("THOS_IOC_MAX_INDICATORS_PER_SOURCE", "250000"))
MAX_TOTAL_INDICATORS = int(os.environ.get("THOS_IOC_MAX_TOTAL_INDICATORS", "1000000"))
MAX_REDIRECTS = int(os.environ.get("THOS_IOC_MAX_REDIRECTS", "3"))
FETCH_TIMEOUT_SECONDS = int(os.environ.get("THOS_IOC_FETCH_TIMEOUT_SECONDS", "45"))
ARCHIVE_RETENTION = int(os.environ.get("THOS_IOC_ARCHIVE_RETENTION", "3"))
ALLOW_PRIVATE_FETCH = os.environ.get("THOS_IOC_ALLOW_PRIVATE_FETCH", "0").lower() in {"1", "true", "yes"}
_write_lock = threading.Lock()

_PATTERNS = {
    "network": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[12][0-9]|3[0-2])\b"),
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
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


DEFAULT_IOC_SOURCES = [
    {
        "id": "openphish-community",
        "name": "OpenPhish Community Feed",
        "kind": "remote",
        "location": "https://openphish.com/feed.txt",
        "category": "phishing",
        "severity": "high",
        "confidence": "high",
        "enabled": True,
        "time": "00:05",
        "frequency": "daily",
        "interval": 2,
        "days": list(range(7)),
        "attribution": "OpenPhish",
        "indicator_types": ["url", "domain"],
        "origin": "IOC sources.xlsx",
    },
    {
        "id": "feodo-recommended",
        "name": "Feodo Tracker Recommended C2",
        "kind": "remote",
        "location": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "category": "botnet-c2",
        "severity": "critical",
        "confidence": "high",
        "enabled": True,
        "time": "00:15",
        "frequency": "hourly",
        "interval": 1,
        "days": list(range(7)),
        "attribution": "abuse.ch Feodo Tracker (CC0)",
        "indicator_types": ["ipv4"],
        "origin": "IOC sources.xlsx",
    },
    {
        "id": "tor-exit-nodes",
        "name": "Tor Project Exit Nodes",
        "kind": "remote",
        "location": "https://check.torproject.org/torbulkexitlist",
        "category": "anonymizer",
        "severity": "medium",
        "confidence": "high",
        "enabled": True,
        "time": "00:25",
        "frequency": "hourly",
        "interval": 1,
        "days": list(range(7)),
        "attribution": "The Tor Project",
        "indicator_types": ["ipv4"],
        "origin": "IOC sources.xlsx",
    },
    {
        "id": "dshield-block",
        "name": "SANS ISC DShield Block List",
        "kind": "remote",
        "location": "https://feeds.dshield.org/feeds/block.txt",
        "category": "internet-scanning",
        "severity": "high",
        "confidence": "medium",
        "enabled": True,
        "time": "00:35",
        "frequency": "hourly",
        "interval": 1,
        "days": list(range(7)),
        "attribution": "SANS Technology Institute Internet Storm Center",
        "indicator_types": ["network"],
        "parser": "dshield_block",
        "origin": "IOC sources.xlsx",
    },
    {
        "id": "firehol-level1",
        "name": "FireHOL Level 1",
        "kind": "remote",
        "location": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "category": "malicious-infrastructure",
        "severity": "high",
        "confidence": "medium",
        "enabled": True,
        "time": "01:00",
        "frequency": "daily",
        "interval": 1,
        "days": list(range(7)),
        "attribution": "FireHOL blocklist-ipsets",
        "indicator_types": ["network", "ipv4"],
        "origin": "IOC sources.xlsx",
    },
]


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
            elif kind == "network":
                try:
                    value = str(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue
            found[kind].add(value)
    found["ipv4"].difference_update(
        match.group(0).split("/", 1)[0]
        for match in _PATTERNS["network"].finditer(text)
    )
    # URLs contain domains; retaining both is useful for SIEM correlation.
    return found


def _dshield_networks(content: bytes) -> dict[str, set[str]]:
    found = {kind: set() for kind in _PATTERNS}
    for line in content.decode("utf-8-sig", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            prefix = fields[2] if len(fields) >= 3 and fields[2].isdigit() else fields[1]
            found["network"].add(str(ipaddress.ip_network(f"{fields[0]}/{prefix}", strict=False)))
        except ValueError:
            continue
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
    current = url
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(FETCH_TIMEOUT_SECONDS, connect=min(10, FETCH_TIMEOUT_SECONDS)),
        follow_redirects=False,
    ) as client:
        for redirect_count in range(MAX_REDIRECTS + 1):
            _validate_remote_url(current)
            async with client.stream(
                "GET",
                current,
                headers={"User-Agent": "THOS-IOC-Agent/1.0", "Accept-Encoding": "identity"},
            ) as response:
                if response.is_redirect:
                    if redirect_count >= MAX_REDIRECTS:
                        raise IOCSourceError("IOC source exceeded the redirect limit")
                    destination = urljoin(current, response.headers.get("location", ""))
                    _validate_remote_url(destination)
                    current = destination
                    continue
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
                name = Path(urlparse(current).path).name or "source.dat"
                return (
                    b"".join(chunks),
                    name,
                    response.headers.get("content-type", "application/octet-stream"),
                )
    raise IOCSourceError("IOC source could not be fetched")


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


def load_blocklist() -> dict:
    blocklist_path = Path(os.environ.get("THOS_IOC_BLOCKLIST_PATH", str(BLOCKLIST_PATH)))
    try:
        value = json.loads(blocklist_path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {"indicators": {}}
    except (OSError, json.JSONDecodeError):
        return {"indicators": {}}


def _best(values: list[str], ranks: dict[str, int], default: str) -> str:
    return max(values or [default], key=lambda item: ranks.get(str(item).lower(), -1))


def _merge_blocklist(source: dict, indicators: dict[str, set[str]], fetched_at: str) -> int:
    blocklist_path = Path(os.environ.get("THOS_IOC_BLOCKLIST_PATH", str(BLOCKLIST_PATH)))
    blocklist_path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        existing = load_blocklist()
        entries = existing.setdefault("indicators", {})
        source_id = str(source["id"])
        # A successful refresh is a replacement for this source, not an
        # append-only merge. This removes expired indicators while retaining
        # corroboration from other feeds.
        for value in list(entries):
            prior = entries.get(value)
            if not isinstance(prior, dict):
                continue
            details = {
                str(key): item for key, item in (prior.get("source_details") or {}).items()
                if str(key) != source_id and isinstance(item, dict)
            }
            if not details:
                entries.pop(value, None)
                continue
            prior["source_details"] = details
            prior["sources"] = sorted(details)
        count = 0
        for indicator_type, values in indicators.items():
            for value in sorted(values):
                if count >= MAX_INDICATORS_PER_SOURCE:
                    break
                prior = entries.get(value, {}) if isinstance(entries.get(value), dict) else {}
                details = {
                    str(key): item for key, item in (prior.get("source_details") or {}).items()
                    if isinstance(item, dict)
                }
                details[source_id] = {
                    "name": source.get("name") or source_id,
                    "location": source.get("location", ""),
                    "category": source.get("category", "uncategorized"),
                    "severity": source.get("severity", "medium"),
                    "confidence": source.get("confidence", "medium"),
                    "attribution": source.get("attribution", ""),
                    "last_seen_by_thos": fetched_at,
                }
                severities = [str(item.get("severity", "medium")).lower() for item in details.values()]
                confidences = [str(item.get("confidence", "medium")).lower() for item in details.values()]
                categories = sorted({
                    str(item.get("category", "uncategorized")).strip().lower()
                    for item in details.values()
                })
                entries[value] = {
                    **prior,
                    "type": indicator_type,
                    "sources": sorted(details),
                    "source_details": details,
                    "source_name": source.get("name") or source_id,
                    "source_url": source.get("location", ""),
                    "category": categories[0] if len(categories) == 1 else ", ".join(categories),
                    "categories": categories,
                    "severity": _best(severities, _SEVERITY_RANK, "medium"),
                    "confidence": _best(confidences, _CONFIDENCE_RANK, "medium"),
                    "first_seen_by_thos": prior.get("first_seen_by_thos") or fetched_at,
                    "last_seen_by_thos": fetched_at,
                }
                count += 1
            if count >= MAX_INDICATORS_PER_SOURCE:
                break
        if len(entries) > MAX_TOTAL_INDICATORS:
            ordered = sorted(
                entries.items(),
                key=lambda item: str((item[1] or {}).get("last_seen_by_thos", "")),
                reverse=True,
            )
            entries.clear()
            entries.update(ordered[:MAX_TOTAL_INDICATORS])
        existing["updated_at"] = fetched_at
        existing["indicator_count"] = len(entries)
        temp = blocklist_path.with_suffix(".tmp")
        temp.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(blocklist_path)
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
    indicators = (
        _dshield_networks(content)
        if source.get("parser") == "dshield_block"
        else extract_indicators(content, filename)
    )
    allowed_types = {
        str(item).strip().lower() for item in source.get("indicator_types", [])
        if str(item).strip()
    }
    if allowed_types:
        indicators = {
            kind: values if kind in allowed_types else set()
            for kind, values in indicators.items()
        }
    extracted = _merge_blocklist(source, indicators, fetched_at)
    archived = sorted(
        (item for item in archive_dir.iterdir() if item.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for expired in archived[max(1, ARCHIVE_RETENTION):]:
        expired.unlink(missing_ok=True)
    return {
        "source_id": source["id"],
        "fetched_at": fetched_at,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_type": content_type,
        "raw_path": str(raw_path),
        "extracted_count": extracted,
        "truncated": sum(len(values) for values in indicators.values()) > MAX_INDICATORS_PER_SOURCE,
        "unique_by_type": {kind: len(values) for kind, values in indicators.items()},
    }
