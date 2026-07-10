"""
File-based log parser tool.

Backs the "folder" / "local files" log source: an analyst points THOS at
a directory (instead of a live SIEM API) containing raw log artifacts —
EVTX exports, flat .log/.txt/syslog, CSV, CEF, JSON/ECS, XML, and pcap —
and every supported file is parsed into the same normalized record shape
used everywhere else in the pipeline:

    {
        "timestamp": <iso8601 str | None>,
        "host":      <str | None>,
        "user":      <str | None>,
        "event":     <str | None>,
        "src_ip":    <str | None>,
        "dst_ip":    <str | None>,
        "detail":    <str>            # human-readable / raw payload
        "source_file": <str>          # originating filename
        "source_type": <str>          # evtx|log|syslog|csv|cef|json|ecs|xml|txt|pcap
    }

Design goals:
  - Best-effort, defensive parsing: a single malformed file/record must
    never abort the whole folder scan.
  - No hard dependency on optional third-party libs at import time —
    python-evtx (EVTX) and scapy (pcap) are imported lazily so the rest
    of the platform keeps working (mock/splunk/qradar/logrhythm paths)
    even if those extras aren't installed.
  - Cheap keyword/regex relevance filtering so a folder with thousands
    of records can still be driven by a generated hunting query, instead
    of always shipping everything downstream.
"""
from __future__ import annotations

import os
import csv
import re
import json
import glob
import datetime
import ipaddress
import xml.etree.ElementTree as ET

# Extensions we know how to parse, keyed by the "source_type" they map to.
EXTENSION_MAP = {
    ".evtx": "evtx",
    ".log": "log",
    ".syslog": "syslog",
    ".csv": "csv",
    ".cef": "cef",
    ".json": "json",
    ".ecs": "ecs",
    ".ndjson": "json",
    ".jsonl": "json",
    ".xml": "xml",
    ".txt": "txt",
    ".pcap": "pcap",
    ".pcapng": "pcap",
}


class LogSourcePathError(Exception):
    """Raised when a caller-supplied folder path falls outside the
    allowlisted log-source root(s)."""


def _allowed_roots() -> list[str]:
    # LOG_SOURCE_ALLOWED_ROOTS supports multiple roots separated by
    # os.pathsep, for deployments that mount more than one evidence
    # directory. Falls back to LOG_SOURCE_DIR (the single default folder
    # mode already used) so existing deployments keep working unchanged.
    raw = os.environ.get("LOG_SOURCE_ALLOWED_ROOTS") or os.environ.get("LOG_SOURCE_DIR", "/data/log_sources")
    return [os.path.realpath(p.strip()) for p in raw.split(os.pathsep) if p.strip()]


def validate_log_source_path(folder: str) -> str:
    """Resolve `folder` and confirm it's inside an allowlisted root.

    log_source_path is caller-supplied and, with no auth in front of these
    endpoints, previously let anyone point folder-mode at any
    container-readable path (e.g. "/etc", "/", "/app"). Resolving symlinks
    and requiring containment inside an explicit allowlist closes that off
    without needing auth to already be in place. Raises LogSourcePathError
    with a caller-facing reason instead of silently doing nothing, so a
    rejected path is visible rather than looking like "folder is just
    empty".
    """
    if not folder or not str(folder).strip():
        raise LogSourcePathError("no folder path provided")
    real = os.path.realpath(folder)
    roots = _allowed_roots()
    if not any(real == root or real.startswith(root + os.sep) for root in roots):
        raise LogSourcePathError(
            f"'{folder}' resolves outside the allowed log-source root(s) "
            f"({', '.join(roots)}); refusing to read arbitrary server-side paths."
        )
    return real

MAX_RECORDS_PER_FILE = 5000  # safety cap so one huge file can't hang a hunt
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    r"|\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"  # syslog: "Jul  7 14:22:01"
)


def _norm(timestamp=None, host=None, user=None, event=None, src_ip=None,
          dst_ip=None, detail="", source_file="", source_type="") -> dict:
    return {
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "event": event,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "detail": detail,
        "source_file": source_file,
        "source_type": source_type,
    }


def _guess_ips(text: str) -> list[str]:
    return IP_RE.findall(text or "")


def _guess_timestamp(text: str) -> str | None:
    m = TIMESTAMP_RE.search(text or "")
    return m.group(0) if m else None


# ---------------------------------------------------------------------
# Per-format parsers. Each takes a file path and yields normalized dicts.
# ---------------------------------------------------------------------

def _parse_evtx(path: str):
    try:
        from Evtx.Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view  # noqa: F401
    except ImportError:
        yield _norm(
            detail="python-evtx is not installed — cannot parse EVTX files. "
                    "Install with `pip install python-evtx`.",
            source_file=os.path.basename(path), source_type="evtx",
        )
        return

    count = 0
    try:
        with Evtx(path) as log:
            for record in log.records():
                if count >= MAX_RECORDS_PER_FILE:
                    break
                try:
                    xml_str = record.xml()
                except Exception:  # noqa: BLE001
                    continue
                try:
                    root = ET.fromstring(xml_str)
                except ET.ParseError:
                    continue
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                event_id_el = root.find(".//e:System/e:EventID", ns)
                time_el = root.find(".//e:System/e:TimeCreated", ns)
                computer_el = root.find(".//e:System/e:Computer", ns)
                user_val = None
                src_ip_val = None
                for data_el in root.findall(".//e:EventData/e:Data", ns):
                    name = data_el.get("Name", "")
                    if name in ("TargetUserName", "SubjectUserName", "AccountName") and data_el.text:
                        user_val = user_val or data_el.text
                    if name in ("IpAddress", "SourceAddress", "SourceIp") and data_el.text:
                        src_ip_val = src_ip_val or data_el.text

                yield _norm(
                    timestamp=(time_el.get("SystemTime") if time_el is not None else None),
                    host=(computer_el.text if computer_el is not None else None),
                    user=user_val,
                    event=(f"EventID-{event_id_el.text}" if event_id_el is not None else "unknown"),
                    src_ip=src_ip_val,
                    detail=xml_str[:2000],
                    source_file=os.path.basename(path),
                    source_type="evtx",
                )
                count += 1
    except Exception as e:  # noqa: BLE001
        yield _norm(
            detail=f"Failed to parse EVTX file: {e}",
            source_file=os.path.basename(path), source_type="evtx",
        )


def _parse_csv(path: str):
    fieldname_aliases = {
        "timestamp": {"timestamp", "time", "@timestamp", "date", "datetime", "event_time"},
        "host": {"host", "hostname", "computer", "device", "src_host"},
        "user": {"user", "username", "account", "login", "user_name"},
        "event": {"event", "event_id", "event_name", "eventid", "action", "message"},
        "src_ip": {"src_ip", "source_ip", "srcip", "sourceaddress", "ip"},
        "dst_ip": {"dst_ip", "dest_ip", "destination_ip", "destip"},
    }

    def _pick(row: dict, keys: set[str]):
        for k, v in row.items():
            if k and k.strip().lower() in keys:
                return v
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= MAX_RECORDS_PER_FILE:
                    break
                detail = json.dumps(row, default=str)
                yield _norm(
                    timestamp=_pick(row, fieldname_aliases["timestamp"]),
                    host=_pick(row, fieldname_aliases["host"]),
                    user=_pick(row, fieldname_aliases["user"]),
                    event=_pick(row, fieldname_aliases["event"]),
                    src_ip=_pick(row, fieldname_aliases["src_ip"]),
                    dst_ip=_pick(row, fieldname_aliases["dst_ip"]),
                    detail=detail,
                    source_file=os.path.basename(path),
                    source_type="csv",
                )
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to parse CSV file: {e}",
                    source_file=os.path.basename(path), source_type="csv")


def _parse_cef(path: str):
    # CEF: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Ext k=v k=v ...
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= MAX_RECORDS_PER_FILE:
                    break
                line = line.strip()
                if not line:
                    continue
                if "CEF:" in line:
                    line = line[line.index("CEF:"):]
                parts = line.split("|")
                name = parts[5] if len(parts) > 5 else "cef_event"
                ext = parts[7] if len(parts) > 7 else ""
                # CEF extension values can contain spaces (e.g. "rt=Jul 01
                # 2026 10:10:00"), so a naive split(" ") on "k=v" pairs
                # breaks. Split right before each subsequent "key=" token
                # instead, using a lookahead for "<word>=".
                ext_fields = {}
                for kv in re.split(r"(?=\b\w+=)", ext):
                    kv = kv.strip()
                    if "=" in kv:
                        k, _, v = kv.partition("=")
                        ext_fields[k.strip()] = v.strip()
                yield _norm(
                    timestamp=ext_fields.get("rt") or ext_fields.get("end") or _guess_timestamp(line),
                    host=ext_fields.get("dvchost") or ext_fields.get("shost"),
                    user=ext_fields.get("suser") or ext_fields.get("duser"),
                    event=name,
                    src_ip=ext_fields.get("src"),
                    dst_ip=ext_fields.get("dst"),
                    detail=line[:2000],
                    source_file=os.path.basename(path),
                    source_type="cef",
                )
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to parse CEF file: {e}",
                    source_file=os.path.basename(path), source_type="cef")


def _flatten_ecs(d: dict, prefix: str = "") -> dict:
    flat = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            flat.update(_flatten_ecs(v, key))
        else:
            flat[key] = v
    return flat


def _parse_json(path: str):
    """Handles plain JSON (array or single object), JSON-lines/NDJSON, and
    ECS-shaped documents (nested host.*, user.*, source.*, destination.*)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to read JSON file: {e}",
                    source_file=os.path.basename(path), source_type="json")
        return

    records = []
    stripped = raw.strip()
    try:
        if stripped.startswith("["):
            records = json.loads(stripped)
        elif stripped.startswith("{"):
            # Could be a single object, or NDJSON of objects on separate lines.
            lines = [ln for ln in stripped.splitlines() if ln.strip()]
            if len(lines) > 1:
                for ln in lines:
                    try:
                        records.append(json.loads(ln))
                    except json.JSONDecodeError:
                        continue
            else:
                records = [json.loads(stripped)]
        else:
            for ln in stripped.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    records.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    except json.JSONDecodeError as e:
        yield _norm(detail=f"Failed to parse JSON file: {e}",
                    source_file=os.path.basename(path), source_type="json")
        return

    is_ecs = path.lower().endswith(".ecs")
    for i, rec in enumerate(records):
        if i >= MAX_RECORDS_PER_FILE:
            break
        if not isinstance(rec, dict):
            continue
        flat = _flatten_ecs(rec)
        timestamp = flat.get("@timestamp") or flat.get("timestamp") or flat.get("time")
        host = flat.get("host.name") or flat.get("host.hostname") or flat.get("host") or flat.get("hostname")
        user = flat.get("user.name") or flat.get("user") or flat.get("username")
        event = (flat.get("event.action") or flat.get("event.category") or
                 flat.get("event") or flat.get("event_type") or "json_event")
        src_ip = flat.get("source.ip") or flat.get("src_ip") or flat.get("source_ip")
        dst_ip = flat.get("destination.ip") or flat.get("dst_ip") or flat.get("destination_ip")
        yield _norm(
            timestamp=timestamp, host=host, user=user, event=event,
            src_ip=src_ip, dst_ip=dst_ip,
            detail=json.dumps(rec, default=str)[:2000],
            source_file=os.path.basename(path),
            source_type="ecs" if is_ecs else "json",
        )


def _parse_xml(path: str):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to parse XML file: {e}",
                    source_file=os.path.basename(path), source_type="xml")
        return

    # Treat each direct child of root as one "record"; if root has no
    # children, treat the whole document as a single record.
    elements = list(root) if len(root) else [root]
    for i, el in enumerate(elements):
        if i >= MAX_RECORDS_PER_FILE:
            break
        attrs = dict(el.attrib)
        for child in el:
            if child.text and child.text.strip():
                attrs[child.tag.split("}")[-1]] = child.text.strip()
        text_blob = ET.tostring(el, encoding="unicode")[:2000]
        yield _norm(
            timestamp=attrs.get("timestamp") or attrs.get("time") or _guess_timestamp(text_blob),
            host=attrs.get("host") or attrs.get("computer") or attrs.get("hostname"),
            user=attrs.get("user") or attrs.get("username"),
            event=attrs.get("event") or attrs.get("eventid") or el.tag.split("}")[-1],
            src_ip=attrs.get("src_ip") or attrs.get("sourceip"),
            dst_ip=attrs.get("dst_ip") or attrs.get("destinationip"),
            detail=text_blob,
            source_file=os.path.basename(path),
            source_type="xml",
        )


def _parse_text_line(path: str, source_type: str):
    """Shared fallback for .log / .syslog / .txt — one record per line,
    with best-effort timestamp/IP/user extraction via regex."""
    user_re = re.compile(r"\buser[=: ]+([\w.\\-]+)", re.IGNORECASE)
    host_re = re.compile(r"\bhost(?:name)?[=: ]+([\w.\\-]+)", re.IGNORECASE)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= MAX_RECORDS_PER_FILE:
                    break
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                ips = _guess_ips(line)
                user_m = user_re.search(line)
                host_m = host_re.search(line)
                # syslog convention: "<ts> <hostname> <process>[pid]: msg"
                syslog_host = None
                syslog_parts = line.split()
                if source_type == "syslog" and len(syslog_parts) > 3:
                    syslog_host = syslog_parts[3]
                yield _norm(
                    timestamp=_guess_timestamp(line),
                    host=host_m.group(1) if host_m else syslog_host,
                    user=user_m.group(1) if user_m else None,
                    event=source_type,
                    src_ip=ips[0] if ips else None,
                    dst_ip=ips[1] if len(ips) > 1 else None,
                    detail=line[:2000],
                    source_file=os.path.basename(path),
                    source_type=source_type,
                )
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to parse {source_type} file: {e}",
                    source_file=os.path.basename(path), source_type=source_type)


def _parse_pcap(path: str):
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP  # noqa: N811
    except ImportError:
        yield _norm(
            detail="scapy is not installed — cannot parse pcap files. "
                    "Install with `pip install scapy`.",
            source_file=os.path.basename(path), source_type="pcap",
        )
        return

    count = 0
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                if count >= MAX_RECORDS_PER_FILE:
                    break
                ts = getattr(pkt, "time", None)
                ts_iso = (
                    datetime.datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
                    if ts is not None else None
                )
                src_ip = dst_ip = None
                proto = "other"
                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
                if TCP in pkt:
                    proto = f"tcp/{pkt[TCP].sport}->{pkt[TCP].dport}"
                elif UDP in pkt:
                    proto = f"udp/{pkt[UDP].sport}->{pkt[UDP].dport}"

                yield _norm(
                    timestamp=ts_iso,
                    event=f"packet:{proto}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    detail=pkt.summary()[:2000],
                    source_file=os.path.basename(path),
                    source_type="pcap",
                )
                count += 1
    except Exception as e:  # noqa: BLE001
        yield _norm(detail=f"Failed to parse pcap file: {e}",
                    source_file=os.path.basename(path), source_type="pcap")


_PARSERS = {
    "evtx": _parse_evtx,
    "csv": _parse_csv,
    "cef": _parse_cef,
    "json": _parse_json,
    "ecs": _parse_json,
    "xml": _parse_xml,
    "pcap": _parse_pcap,
    "log": lambda p: _parse_text_line(p, "log"),
    "syslog": lambda p: _parse_text_line(p, "syslog"),
    "txt": lambda p: _parse_text_line(p, "txt"),
}


def list_supported_files(folder: str) -> list[str]:
    try:
        folder = validate_log_source_path(folder)
    except LogSourcePathError:
        return []
    if not folder or not os.path.isdir(folder):
        return []
    files = []
    for path in glob.glob(os.path.join(folder, "**", "*"), recursive=True):
        if os.path.isfile(path) and os.path.splitext(path)[1].lower() in EXTENSION_MAP:
            files.append(path)
    return sorted(files)


def parse_folder(folder: str, max_files: int | None = None) -> list[dict]:
    """Parse every supported file in `folder` (recursively) into a flat
    list of normalized log record dicts."""
    files = list_supported_files(folder)
    if max_files:
        files = files[:max_files]

    records: list[dict] = []
    for path in files:
        ext = os.path.splitext(path)[1].lower()
        source_type = EXTENSION_MAP[ext]
        parser = _PARSERS.get(source_type)
        if not parser:
            continue
        for rec in parser(path):
            records.append(rec)
    return records


def _matches_query(record: dict, terms: list[str]) -> bool:
    if not terms:
        return True
    haystack = " ".join(str(v) for v in record.values() if v).lower()
    return any(term.lower() in haystack for term in terms if term.strip())


def query_terms_from_text(query: str) -> list[str]:
    """Turn a free-text/keyword 'query' (as generated for the folder
    source, or typed directly by the analyst) into a list of substring
    terms used for simple relevance filtering."""
    if not query:
        return []
    # Split on common separators an LLM or analyst might use: commas,
    # " OR ", " AND ", pipes, newlines.
    parts = re.split(r"\s+OR\s+|\s+AND\s+|[,\n|]", query)
    return [p.strip().strip('"').strip("'") for p in parts if p.strip()]


def fetch_from_folder(folder: str, query: str = "", limit: int = 100) -> dict:
    """Scan `folder`, parse every supported file, filter by `query`
    (best-effort substring match against the normalized record), and
    return up to `limit` matching records — falling back to the most
    recent-looking records unfiltered if the query matches nothing, so
    an over-specific generated query doesn't silently return zero logs.
    """
    try:
        folder = validate_log_source_path(folder)
    except LogSourcePathError as e:
        return {
            "siem_type": "folder",
            "query": query,
            "folder": folder,
            "files_scanned": 0,
            "total_parsed": 0,
            "record_count": 0,
            "used_fallback_unfiltered": False,
            "logs": [],
            "error": str(e),
        }

    all_records = parse_folder(folder)
    terms = query_terms_from_text(query)
    matched = [r for r in all_records if _matches_query(r, terms)]

    used_fallback = False
    if terms and not matched:
        matched = all_records
        used_fallback = True

    matched = matched[:limit]
    return {
        "siem_type": "folder",
        "query": query,
        "folder": folder,
        "files_scanned": len(list_supported_files(folder)),
        "total_parsed": len(all_records),
        "record_count": len(matched),
        "used_fallback_unfiltered": used_fallback,
        "logs": matched,
    }
