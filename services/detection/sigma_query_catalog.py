"""Build and read the reusable Sigma -> SIEM query catalog.

The catalog is generated once by Compose after the pinned SigmaHQ corpus is
ready. Runtime hunts only select and execute precompiled queries; they never
compile thousands of rules or retrieve unfiltered enterprise telemetry.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

from services.observability import cache
from services.siem import siem_kb
from services.siem.schema_discovery import get_cached_siem_schema


CATALOG_VERSION = 2
CATALOG_DIR = Path(os.environ.get("SIGMA_QUERY_CATALOG_DIR", "/data/sigma_queries"))
HQ_RULES_DIR = Path(os.environ.get(
    "SIGMAHQ_RULES_DIR", Path(__file__).with_name("sigma_rules_hq")
))
LOCAL_RULES_DIR = Path(__file__).with_name("sigma_rules")
SUPPORTED_BACKENDS = {"splunk", "wazuh"}
COMPILED_CACHE_NAMESPACE = "compiled_detections"
COMPILED_INDEX_NAMESPACE = "compiled_detection_index"
COMPILED_CACHE_TTL_SECONDS = 35 * 24 * 60 * 60

# Wazuh Indexer field names for common Windows Sigma fields. Unmapped fields
# remain visible in the query and are reported in catalog metadata, allowing a
# deployment-specific pySigma pipeline to supersede this baseline mapping.
WAZUH_FIELD_MAP = {
    "EventID": "data.win.system.eventID",
    "Computer": "agent.name",
    "ComputerName": "agent.name",
    "Hostname": "agent.name",
    "User": "data.win.eventdata.targetUserName",
    "UserName": "data.win.eventdata.targetUserName",
    "TargetUserName": "data.win.eventdata.targetUserName",
    "SubjectUserName": "data.win.eventdata.subjectUserName",
    "Image": "data.win.eventdata.image",
    "OriginalFileName": "data.win.eventdata.originalFileName",
    "CommandLine": "data.win.eventdata.commandLine",
    "ParentImage": "data.win.eventdata.parentImage",
    "ParentCommandLine": "data.win.eventdata.parentCommandLine",
    "SourceIp": "data.srcip",
    "DestinationIp": "data.dstip",
}

SPLUNK_FIELD_MAP = {
    "EventID": "EventCode",
    "Computer": "host",
    "ComputerName": "host",
    "Hostname": "host",
    "User": "user",
    "UserName": "user",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "Image": "process_name",
    "OriginalFileName": "process_name",
    "CommandLine": "process",
    "ParentImage": "parent_process_name",
    "ParentCommandLine": "parent_process",
    "SourceIp": "src_ip",
    "DestinationIp": "dest_ip",
}

SIGMA_TO_NORMALIZED = {
    "EventID": "event_id",
    "Computer": "host",
    "ComputerName": "host",
    "Hostname": "host",
    "User": "user",
    "UserName": "user",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "Image": "process_name",
    "OriginalFileName": "process_name",
    "CommandLine": "command_line",
    "ParentImage": "parent_process_name",
    "ParentCommandLine": "parent_command_line",
    "SourceIp": "src_ip",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "SourcePort": "src_port",
    "QueryName": "dns_query",
}


def _rule_files() -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    for source, root in (("THOS", LOCAL_RULES_DIR), ("SigmaHQ", HQ_RULES_DIR)):
        if root.exists():
            found.extend((source, path) for path in sorted(root.rglob("*.yml")))
            found.extend((source, path) for path in sorted(root.rglob("*.yaml")))
    return found


def _normalise_rule(source: str, raw: dict) -> tuple[str, dict]:
    original_id = str(raw.get("id") or "")
    if not original_id:
        original_id = hashlib.sha256(
            yaml.safe_dump(raw, sort_keys=True).encode("utf-8")
        ).hexdigest()[:24]
    normalised = dict(raw)
    # Local THOS rule IDs intentionally use readable IDs. pySigma correctly
    # requires UUIDs, so use a deterministic compile-only UUID while retaining
    # the real ID in catalog metadata and runtime results.
    try:
        uuid.UUID(original_id)
    except ValueError:
        normalised["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"thos:{original_id}"))
    normalised.setdefault("status", "experimental")
    return original_id, normalised


def _apply_field_map(query: str, field_map: dict[str, str]) -> str:
    mapped = query
    for source, target in sorted(field_map.items(), key=lambda item: -len(item[0])):
        mapped = re.sub(
            rf"(?<![A-Za-z0-9_.]){re.escape(source)}(?=\s*:)",
            target,
            mapped,
        )
    return mapped


def _wazuh_query(lucene: str, field_map: dict[str, str] | None = None) -> str:
    mapped = _apply_field_map(lucene, {**WAZUH_FIELD_MAP, **(field_map or {})})
    return json.dumps({
        "query": {
            "query_string": {
                "query": mapped,
                "analyze_wildcard": True,
            }
        }
    }, separators=(",", ":"))


def _compile(raw: dict, backend: str, field_map: dict[str, str] | None = None) -> str:
    collection = SigmaCollection.from_yaml(yaml.safe_dump(raw, sort_keys=False))
    if backend == "splunk":
        output = SplunkBackend().convert(collection)
        output = [_apply_field_map(str(item), field_map or {}) for item in output]
    elif backend == "wazuh":
        output = OpensearchLuceneBackend().convert(collection)
        output = [_wazuh_query(item, field_map) for item in output]
    else:
        raise NotImplementedError(
            f"No audited pySigma backend is bundled for {backend}; conversion failed closed"
        )
    if len(output) != 1 or not str(output[0]).strip():
        raise ValueError(f"backend emitted {len(output)} queries; one query per rule is required")
    return str(output[0]).strip()


def _selection_fields(value: Any) -> set[str]:
    """Extract field names from Sigma detection selections."""
    fields: set[str] = set()
    if not isinstance(value, dict):
        return fields
    for selection_name, selection in value.items():
        if selection_name == "condition":
            continue
        mappings = (
            [selection]
            if isinstance(selection, dict)
            else [item for item in selection if isinstance(item, dict)]
            if isinstance(selection, list)
            else []
        )
        for mapping in mappings:
            for field in mapping:
                if field != "condition":
                    fields.add(str(field).split("|", 1)[0])
    return {field for field in fields if field and not field.isdigit()}


def _inventory_names(snapshot: dict) -> list[str]:
    return [
        str(item.get("name"))
        for item in snapshot.get("fields", [])
        if isinstance(item, dict) and item.get("name")
    ]


def _best_inventory_match(source: str, fields: list[str]) -> str | None:
    exact = {field.casefold(): field for field in fields}
    if source.casefold() in exact:
        return exact[source.casefold()]
    leaf_matches = [
        field for field in fields
        if field.rsplit(".", 1)[-1].casefold() == source.casefold()
    ]
    if leaf_matches:
        return sorted(leaf_matches, key=lambda value: (value.count("."), len(value)))[0]
    return None


def _schema_context(siem_type: str) -> tuple[dict, str, bool]:
    snapshot = get_cached_siem_schema(siem_type)
    configured = siem_kb.get_field_mapping(siem_type)
    configured.pop("available_fields", None)
    version_payload = {
        "schema_version": snapshot.get("schema_version", "baseline"),
        "mapping": configured,
    }
    version = hashlib.sha256(
        json.dumps(version_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return snapshot, version, bool(snapshot.get("stale", True))


def _resolve_field_map(raw: dict, siem_type: str, snapshot: dict) -> tuple[dict[str, str], list[str]]:
    sigma_fields = sorted(_selection_fields(raw.get("detection", {})), key=str.casefold)
    available = _inventory_names(snapshot)
    configured = siem_kb.get_field_mapping(siem_type)
    baseline = WAZUH_FIELD_MAP if siem_type == "wazuh" else SPLUNK_FIELD_MAP
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for source in sigma_fields:
        direct = _best_inventory_match(source, available)
        normalized = SIGMA_TO_NORMALIZED.get(source, source)
        configured_value = configured.get(normalized)
        configured_candidates = [
            candidate.strip()
            for candidate in str(configured_value or "").split(" / ")
            if candidate.strip()
        ]
        candidates = [
            *configured_candidates,
            baseline.get(source),
            direct,
        ]
        target = next((
            (_best_inventory_match(candidate, available) or candidate)
            for candidate in candidates
            if candidate and (not available or _best_inventory_match(candidate, available))
        ), None)
        if target:
            resolved[source] = target
        elif not snapshot.get("hit") and next((candidate for candidate in candidates if candidate), None):
            resolved[source] = next(candidate for candidate in candidates if candidate)
        else:
            missing.append(source)
    return resolved, missing


def _find_raw_rule(rule_id: str) -> tuple[str, Path, dict, bytes]:
    for source, path in _rule_files():
        content = path.read_bytes()
        raw = yaml.safe_load(content) or {}
        if not isinstance(raw, dict):
            continue
        original_id, _normalised = _normalise_rule(source, raw)
        if original_id == rule_id:
            return source, path, raw, content
    raise LookupError(f"Sigma rule {rule_id} was not found in the active corpus")


def _compiled_cache_payload(rule_id: str, backend: str, schema_version: str) -> str:
    return f"{rule_id}:{backend}:{schema_version}"


def _compile_rule_data(
    source: str,
    path: Path,
    raw: dict,
    content: bytes,
    backend: str,
    snapshot: dict,
    schema_version: str,
    schema_stale: bool,
) -> dict:
    original_id, normalised = _normalise_rule(source, raw)
    field_map, missing = _resolve_field_map(raw, backend, snapshot)
    if missing:
        result = {
            "rule_id": original_id,
            "title": str(raw.get("title") or "Untitled rule"),
            "backend": backend,
            "status": "uncompilable",
            "query": None,
            "missing_fields": missing,
            "schema_version": schema_version,
            "schema_stale": schema_stale,
            "rule_source": source,
            "rule_path": str(path),
        }
    else:
        result = {
            "rule_id": original_id,
            "title": str(raw.get("title") or "Untitled rule"),
            "level": str(raw.get("level") or "medium"),
            "tags": [str(tag).lower() for tag in (raw.get("tags") or [])],
            "backend": backend,
            "status": "ready",
            "query": _compile(normalised, backend, field_map),
            "missing_fields": [],
            "schema_version": schema_version,
            "schema_stale": schema_stale,
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "rule_source": source,
            "rule_path": str(path),
            "rule_hash": hashlib.sha256(content).hexdigest(),
            "field_map": field_map,
        }
    cache.cache_set(
        COMPILED_CACHE_NAMESPACE,
        _compiled_cache_payload(original_id, backend, schema_version),
        result,
        ttl=COMPILED_CACHE_TTL_SECONDS,
    )
    return result


def compile_sigma_rule_to_query(rule_id: str, siem_type: str) -> dict:
    """Compile one rule against the cached live schema and cache the result."""
    backend = siem_type.lower()
    if backend not in SUPPORTED_BACKENDS:
        raise NotImplementedError(
            f"No audited pySigma backend is bundled for {backend}; conversion failed closed"
        )
    source, path, raw, content = _find_raw_rule(rule_id)
    snapshot, schema_version, schema_stale = _schema_context(backend)
    return _compile_rule_data(
        source, path, raw, content, backend, snapshot, schema_version, schema_stale
    )


def compile_sigma_rules_for_siem(siem_type: str) -> dict:
    """Compile the active corpus in a bounded-memory weekly pass."""
    backend = siem_type.lower()
    if backend not in SUPPORTED_BACKENDS:
        return {
            "siem_type": backend,
            "status": "unsupported_backend",
            "ready": 0,
            "uncompilable": 0,
            "errors": [f"No audited pySigma backend is bundled for {backend}"],
        }
    cap = max(0, int(os.environ.get("SIGMA_WEEKLY_MAX_RULES", "0")))
    files = _rule_files()
    if cap:
        files = files[:cap]
    snapshot, schema_version, schema_stale = _schema_context(backend)
    ready = 0
    failures: list[dict] = []
    for source, path in files:
        try:
            content = path.read_bytes()
            raw = yaml.safe_load(content) or {}
            if not isinstance(raw, dict):
                raise ValueError("rule root is not a mapping")
            rule_id, _normalised = _normalise_rule(source, raw)
            result = _compile_rule_data(
                source,
                path,
                raw,
                content,
                backend,
                snapshot,
                schema_version,
                schema_stale,
            )
            if result["status"] == "ready":
                ready += 1
            else:
                failures.append({
                    "rule_id": rule_id,
                    "title": result.get("title"),
                    "missing_fields": result.get("missing_fields", []),
                    "error": None,
                })
        except Exception as exc:
            failures.append({
                "rule_id": path.stem,
                "title": path.stem,
                "missing_fields": [],
                "error": str(exc)[:1000],
            })
    index = {
        "siem_type": backend,
        "status": "complete",
        "schema_version": schema_version,
        "schema_stale": schema_stale,
        "rules_scanned": len(files),
        "ready": ready,
        "uncompilable": len(failures),
        "failures": failures[:500],
        "failures_truncated": max(0, len(failures) - 500),
        "compiled_at": datetime.now(timezone.utc).isoformat(),
        "resource_limit": cap or None,
    }
    cache.cache_set(
        COMPILED_INDEX_NAMESPACE,
        backend,
        index,
        ttl=COMPILED_CACHE_TTL_SECONDS,
    )
    return index


def flag_uncompilable_rules(siem_type: str) -> list[dict]:
    index = cache.cache_get(COMPILED_INDEX_NAMESPACE, siem_type.lower())
    if not isinstance(index, dict):
        index = compile_sigma_rules_for_siem(siem_type)
    return list(index.get("failures") or [])


def build_catalog(backends: list[str] | None = None) -> dict:
    requested = backends or [
        value.strip().lower() for value in
        os.environ.get("SIGMA_QUERY_BACKENDS", "splunk,wazuh,qradar,logrhythm").split(",")
        if value.strip()
    ]
    files = _rule_files()
    required_hq = int(os.environ.get("SIGMAHQ_MIN_RULES", "0"))
    hq_count = sum(source == "SigmaHQ" for source, _path in files)
    if hq_count < required_hq:
        raise RuntimeError(
            f"SigmaHQ corpus invariant failed: {hq_count} rules found; {required_hq} required"
        )
    source_hash = hashlib.sha256()
    for source, path in files:
        source_hash.update(source.encode("utf-8"))
        source_hash.update(str(path.relative_to(HQ_RULES_DIR if source == "SigmaHQ" else LOCAL_RULES_DIR)).encode("utf-8"))
        source_hash.update(path.read_bytes())
    digest = source_hash.hexdigest()
    target = CATALOG_DIR / "catalog.json"
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
            if (existing.get("version") == CATALOG_VERSION and
                    existing.get("source_hash") == digest and existing.get("backends") == requested):
                print(f"[sigma-query-init] reusing {existing.get('ready', 0)} precompiled queries")
                return existing
        except (OSError, ValueError):
            pass

    entries: list[dict] = []
    for source, path in files:
        try:
            content = path.read_bytes()
            raw = yaml.safe_load(content) or {}
            if not isinstance(raw, dict):
                raise ValueError("rule root is not a mapping")
            original_id, normalised = _normalise_rule(source, raw)
            base = {
                "rule_id": original_id,
                "title": str(raw.get("title") or "Untitled rule"),
                "level": str(raw.get("level") or "medium"),
                "tags": [str(tag).lower() for tag in (raw.get("tags") or [])],
                "rule_source": source,
                "rule_path": str(path),
                "rule_hash": hashlib.sha256(content).hexdigest(),
            }
            for backend in requested:
                item = {**base, "backend": backend}
                try:
                    item.update(status="ready", query=_compile(normalised, backend), error=None)
                except Exception as exc:  # one unsupported rule never aborts the corpus
                    item.update(status="unsupported", query=None, error=str(exc)[:1000])
                entries.append(item)
        except Exception as exc:
            entries.append({
                "rule_id": path.stem, "title": path.stem, "level": "unknown",
                "tags": [], "rule_source": source, "rule_path": str(path),
                "rule_hash": None, "backend": "all", "status": "invalid",
                "query": None, "error": str(exc)[:1000],
            })

    payload = {
        "version": CATALOG_VERSION,
        "source_hash": digest,
        "rule_files": len(files),
        "backends": requested,
        "ready": sum(item["status"] == "ready" for item in entries),
        "unsupported": sum(item["status"] != "ready" for item in entries),
        "entries": entries,
    }
    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=CATALOG_DIR, delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        temporary = Path(handle.name)
    temporary.replace(target)
    print(
        f"[sigma-query-init] {payload['rule_files']} rules; {payload['ready']} queries ready; "
        f"{payload['unsupported']} conversion failures"
    )
    return payload


def load_catalog() -> dict:
    target = CATALOG_DIR / "catalog.json"
    if not target.exists():
        raise RuntimeError(
            f"Sigma query catalog is missing at {target}; Compose must complete sigma-query-init"
        )
    return json.loads(target.read_text(encoding="utf-8"))


def find_rule(rule_id: str, backend: str) -> dict:
    if backend in SUPPORTED_BACKENDS:
        _snapshot, schema_version, _stale = _schema_context(backend)
        compiled = cache.cache_get(
            COMPILED_CACHE_NAMESPACE,
            _compiled_cache_payload(rule_id, backend, schema_version),
        )
        if isinstance(compiled, dict):
            if compiled.get("status") != "ready" or not compiled.get("query"):
                raise RuntimeError(
                    f"Sigma rule {rule_id} cannot be converted for {backend}: "
                    f"missing fields {compiled.get('missing_fields', [])}"
                )
            # Preserve the file-catalog shape expected by execution callers.
            return {
                **compiled,
                "title": compiled.get("title", "Untitled rule"),
                "rule_source": compiled.get("rule_source", "unknown"),
            }
    candidates = [item for item in load_catalog().get("entries", [])
                  if item.get("rule_id") == rule_id and item.get("backend") == backend]
    if not candidates:
        raise LookupError(f"Sigma rule {rule_id} has no {backend} catalog entry")
    entry = candidates[0]
    if entry.get("status") != "ready" or not entry.get("query"):
        raise RuntimeError(
            f"Sigma rule {rule_id} cannot be converted for {backend}: {entry.get('error')}"
        )
    return entry


def ready_rule_ids(backend: str) -> list[str]:
    """Return every unique rule that is executable against the current schema."""
    catalog = load_catalog()
    entries = [item for item in catalog.get("entries", []) if item.get("backend") == backend]
    ready: list[str] = []
    seen: set[str] = set()
    schema_version = ""
    if backend in SUPPORTED_BACKENDS:
        _snapshot, schema_version, _stale = _schema_context(backend)
    for item in entries:
        rule_id = str(item.get("rule_id") or "")
        if not rule_id or rule_id in seen:
            continue
        compiled = (
            cache.cache_get(
                COMPILED_CACHE_NAMESPACE,
                _compiled_cache_payload(rule_id, backend, schema_version),
            )
            if schema_version else None
        )
        executable = (
            isinstance(compiled, dict)
            and compiled.get("status") == "ready"
            and bool(compiled.get("query"))
        ) or (
            not isinstance(compiled, dict)
            and item.get("status") == "ready"
            and bool(item.get("query"))
        )
        if executable:
            seen.add(rule_id)
            ready.append(rule_id)
    return ready


def applicable_rules(backend: str, technique_id: str = "", tactic: str = "",
                     limit: int | None = None) -> tuple[list[dict], dict]:
    catalog = load_catalog()
    all_backend = [item for item in catalog.get("entries", []) if item.get("backend") == backend]
    technique_tag = f"attack.{technique_id.lower()}" if technique_id else ""
    tactic_tag = f"attack.{tactic.lower().replace(' ', '_')}" if tactic else ""
    relevant = [item for item in all_backend if
                (technique_tag and technique_tag in item.get("tags", [])) or
                (not technique_tag and tactic_tag and tactic_tag in item.get("tags", []))]
    # A hunt with no ATT&CK tag must not fan out thousands of SIEM requests.
    ready: list[dict] = []
    unsupported = 0
    if backend in SUPPORTED_BACKENDS:
        _snapshot, schema_version, _stale = _schema_context(backend)
        for item in relevant:
            compiled = cache.cache_get(
                COMPILED_CACHE_NAMESPACE,
                _compiled_cache_payload(str(item.get("rule_id")), backend, schema_version),
            )
            if isinstance(compiled, dict):
                if compiled.get("status") == "ready" and compiled.get("query"):
                    ready.append({**item, **compiled})
                else:
                    unsupported += 1
            elif item.get("status") == "ready" and item.get("query"):
                ready.append(item)
            else:
                unsupported += 1
    else:
        ready = [item for item in relevant if item.get("status") == "ready" and item.get("query")]
        unsupported = len(relevant) - len(ready)
    cap = limit or int(os.environ.get("SIGMA_HUNT_MAX_RULES", "64"))
    return ready[:cap], {
        "relevant": len(relevant),
        "ready": len(ready),
        "unsupported": unsupported,
        "truncated": max(0, len(ready) - cap),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["build", "verify"], nargs="?", default="build")
    args = parser.parse_args()
    if args.command == "build":
        payload = build_catalog()
    else:
        payload = load_catalog()
        print(f"[sigma-query-init] verified {payload.get('ready', 0)} ready queries")
    return 0 if payload.get("rule_files", 0) > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
