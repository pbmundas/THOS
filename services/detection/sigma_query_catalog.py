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
from pathlib import Path

import yaml
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection


CATALOG_VERSION = 1
CATALOG_DIR = Path(os.environ.get("SIGMA_QUERY_CATALOG_DIR", "/data/sigma_queries"))
HQ_RULES_DIR = Path(os.environ.get(
    "SIGMAHQ_RULES_DIR", Path(__file__).with_name("sigma_rules_hq")
))
LOCAL_RULES_DIR = Path(__file__).with_name("sigma_rules")
SUPPORTED_BACKENDS = {"splunk", "wazuh"}

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


def _wazuh_query(lucene: str) -> str:
    mapped = lucene
    for source, target in sorted(WAZUH_FIELD_MAP.items(), key=lambda item: -len(item[0])):
        mapped = re.sub(rf"(?<![A-Za-z0-9_.]){re.escape(source)}(?=\s*:)", target, mapped)
    return json.dumps({
        "query": {
            "query_string": {
                "query": mapped,
                "analyze_wildcard": True,
            }
        }
    }, separators=(",", ":"))


def _compile(raw: dict, backend: str) -> str:
    collection = SigmaCollection.from_yaml(yaml.safe_dump(raw, sort_keys=False))
    if backend == "splunk":
        output = SplunkBackend().convert(collection)
    elif backend == "wazuh":
        output = OpensearchLuceneBackend().convert(collection)
        output = [_wazuh_query(item) for item in output]
    else:
        raise NotImplementedError(
            f"No audited pySigma backend is bundled for {backend}; conversion failed closed"
        )
    if len(output) != 1 or not str(output[0]).strip():
        raise ValueError(f"backend emitted {len(output)} queries; one query per rule is required")
    return str(output[0]).strip()


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
    ready = [item for item in relevant if item.get("status") == "ready"]
    cap = limit or int(os.environ.get("SIGMA_HUNT_MAX_RULES", "64"))
    return ready[:cap], {
        "relevant": len(relevant),
        "ready": len(ready),
        "unsupported": sum(item.get("status") != "ready" for item in relevant),
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
