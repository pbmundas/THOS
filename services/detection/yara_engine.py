"""Resource-bounded local and managed-community YARA scanning."""
from __future__ import annotations

import hashlib
from functools import lru_cache
import json
import os
from pathlib import Path
import re
from typing import Any

from services.runtime_config import get_value


LOCAL_RULES_DIR = Path(os.environ.get(
    "YARA_LOCAL_RULES_DIR",
    os.environ.get("YARA_RULES_DIR", str(Path(__file__).with_name("yara_rules"))),
))
# Backward-compatible alias retained for tests and local callers.
RULES_DIR = LOCAL_RULES_DIR
COMMUNITY_RULES_DIR = Path(os.environ.get(
    "YARARULES_RULES_DIR", "/data/yara-community"
))
CATALOG_DIR = Path(os.environ.get("YARA_CATALOG_DIR", "/data/yara-catalog"))
COMMUNITY_MANIFEST = CATALOG_DIR / "catalog.json"
COMMUNITY_COMPILED = CATALOG_DIR / "community.compiled"
MAX_FILE_BYTES = int(os.environ.get("YARA_MAX_FILE_BYTES", str(256 * 1024 * 1024)))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("YARA_SCAN_TIMEOUT_SECONDS", "30"))
MATCH_LIMIT = int(os.environ.get("YARA_MATCH_LIMIT", "200"))
EXTERNALS = {"filename": "", "filepath": "", "extension": ""}
RULE_HEADER = re.compile(
    r"(?m)^\s*(?P<modifiers>(?:(?:private|global)\s+)*)rule\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]+)?\{"
)


class YaraUnavailableError(RuntimeError):
    pass


def _yara():
    try:
        import yara
        return yara
    except ImportError as exc:
        raise YaraUnavailableError("yara-python is not installed in this service") from exc


def rule_paths() -> list[Path]:
    """Return locally managed rules; the community corpus has its own volume."""
    return sorted([
        path for pattern in ("*.yar", "*.yara")
        for path in RULES_DIR.rglob(pattern)
        if path.is_file()
    ])


def _rule_blocks(text: str) -> list[tuple[str, str, set[str]]]:
    results: list[tuple[str, str, set[str]]] = []
    for match in RULE_HEADER.finditer(text):
        depth, end = 0, None
        for index in range(match.end() - 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end:
            results.append((
                match.group("name"),
                text[match.start():end],
                set(match.group("modifiers").split()),
            ))
    return results


def _meta(block: str, name: str) -> str:
    match = re.search(
        rf"(?m)^\s*{re.escape(name)}\s*=\s*(?:\"([^\"]*)\"|([0-9]+))",
        block,
    )
    return (match.group(1) or match.group(2) or "") if match else ""


def _namespace(prefix: str, relative: str) -> str:
    return f"{prefix}_{hashlib.sha256(relative.encode('utf-8')).hexdigest()[:20]}"


def _local_catalog() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in rule_paths():
        relative = path.relative_to(RULES_DIR).as_posix()
        namespace = _namespace("local", relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        for rule_name, block, modifiers in _rule_blocks(text):
            if "private" in modifiers:
                continue
            rules.append({
                "id": rule_name,
                "rule_name": rule_name,
                "title": _meta(block, "title") or rule_name.replace("_", " "),
                "description": _meta(block, "description"),
                "severity": (_meta(block, "severity") or "medium").lower(),
                "status": _meta(block, "status") or "stable",
                "attack": _meta(block, "attack"),
                "source": "THOS local",
                "category": "local",
                "path": str(path),
                "relative_path": relative,
                "namespace": namespace,
                "modifiers": sorted(modifiers),
                "private": False,
                "compilation_status": "ready",
                "compilation_error": "",
            })
    return rules


@lru_cache(maxsize=1)
def _community_payload() -> dict[str, Any]:
    if not COMMUNITY_MANIFEST.is_file():
        return {}
    try:
        return json.loads(COMMUNITY_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def catalog_summary() -> dict[str, Any]:
    payload = _community_payload()
    return {
        "source": payload.get("source", "https://github.com/Yara-Rules/rules"),
        "source_version": payload.get("source_version", ""),
        "rule_files": int(payload.get("rule_files", 0)),
        "ready_files": int(payload.get("ready_files", 0)),
        "invalid_files": int(payload.get("invalid_files", 0)),
        "ready_rules": int(payload.get("ready_rules", 0)) + len(_local_catalog()),
        "invalid_rules": int(payload.get("invalid_rules", 0)),
        "compiled_at": payload.get("compiled_at", ""),
        "catalog_available": COMMUNITY_MANIFEST.is_file() and COMMUNITY_COMPILED.is_file(),
    }


def catalog() -> list[dict[str, Any]]:
    disabled = set(get_value("yara", "disabled_rule_ids", default=[]) or [])
    community = list(_community_payload().get("entries") or [])
    rules = [*_local_catalog(), *community]
    for item in rules:
        ready = item.get("compilation_status", "ready") == "ready"
        item["enabled"] = ready and item["id"] not in disabled
        if item.get("relative_path") and not item.get("path"):
            item["path"] = str(COMMUNITY_RULES_DIR / item["relative_path"])
    return rules


class CompiledBundle:
    """One precompiled community ruleset plus optional local rules."""

    def __init__(
        self,
        rulesets: list[tuple[Any, bool]],
        identities: dict[tuple[str, str], str],
        allowed_ids: set[str],
    ):
        self.rulesets = rulesets
        self.identities = identities
        self.allowed_ids = allowed_ids

    def match(self, filepath: str, timeout: int) -> list[tuple[Any, str]]:
        candidate = Path(filepath)
        external_values = {
            "filename": candidate.name,
            "filepath": str(candidate),
            "extension": candidate.suffix.lower().lstrip("."),
        }
        output: list[tuple[Any, str]] = []
        for rules, uses_externals in self.rulesets:
            kwargs: dict[str, Any] = {"filepath": filepath, "timeout": timeout}
            if uses_externals:
                kwargs["externals"] = external_values
            for match in rules.match(**kwargs):
                identity = self.identities.get(
                    (str(match.namespace), str(match.rule)),
                    str(match.rule),
                )
                if identity in self.allowed_ids:
                    output.append((match, identity))
                    if len(output) >= MATCH_LIMIT:
                        return output
        return output


def compile_enabled(rule_ids: set[str] | None = None) -> CompiledBundle | None:
    yara = _yara()
    active = [
        item for item in catalog()
        if item["enabled"] and (rule_ids is None or item["id"] in rule_ids)
    ]
    if not active:
        return None
    allowed = {str(item["id"]) for item in active}
    identities = {
        (str(item.get("namespace", "default")), str(item.get("rule_name", item["id"]))):
        str(item["id"])
        for item in active
    }
    rulesets: list[tuple[Any, bool]] = []

    community_active = any(item.get("source") == "Yara-Rules/rules" for item in active)
    if community_active and COMMUNITY_COMPILED.is_file():
        rulesets.append((yara.load(str(COMMUNITY_COMPILED)), True))

    local_active = [item for item in active if item.get("source") == "THOS local"]
    if local_active:
        active_namespaces = {str(item["namespace"]) for item in local_active}
        sources: dict[str, str] = {}
        for path in rule_paths():
            relative = path.relative_to(RULES_DIR).as_posix()
            namespace = _namespace("local", relative)
            if namespace in active_namespaces:
                sources[namespace] = path.read_text(encoding="utf-8", errors="replace")
        if sources:
            rulesets.append((yara.compile(sources=sources), False))
    return CompiledBundle(rulesets, identities, allowed) if rulesets else None


def _strings(match) -> list[dict]:
    output = []
    for item in getattr(match, "strings", [])[:200]:
        if hasattr(item, "instances"):
            for instance in item.instances[:50]:
                output.append({
                    "identifier": str(item.identifier),
                    "offset": int(instance.offset),
                    "matched_data_hex": bytes(instance.matched_data)[:128].hex(),
                })
        elif isinstance(item, tuple) and len(item) >= 3:
            output.append({
                "identifier": str(item[1]),
                "offset": int(item[0]),
                "matched_data_hex": bytes(item[2])[:128].hex(),
            })
    return output


def _scan_file_with_bundle(
    path: str | Path,
    compiled: CompiledBundle | None,
) -> dict:
    candidate = Path(path).resolve()
    if not candidate.is_file():
        raise ValueError("YARA scan target is not a file")
    size = candidate.stat().st_size
    if size > MAX_FILE_BYTES:
        return {
            "path": str(candidate), "size_bytes": size, "sha256": "",
            "status": "skipped", "error": f"file exceeds YARA limit ({MAX_FILE_BYTES} bytes)",
            "matches": [],
        }
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    matches = [] if compiled is None else compiled.match(
        filepath=str(candidate), timeout=SCAN_TIMEOUT_SECONDS,
    )
    return {
        "path": str(candidate),
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "status": "matched" if matches else "clean",
        "matches": [{
            "rule_id": catalog_id,
            "raw_rule_id": str(match.rule),
            "namespace": str(match.namespace),
            "tags": [str(tag) for tag in match.tags],
            "meta": dict(match.meta),
            "strings": _strings(match),
        } for match, catalog_id in matches],
    }


def scan_file(path: str | Path, rule_ids: set[str] | None = None) -> dict:
    return _scan_file_with_bundle(path, compile_enabled(rule_ids))


def scan_paths(paths: list[str | Path], rule_ids: set[str] | None = None) -> dict:
    results, errors = [], []
    # Loading the 15+ MB managed database and compiling local rules happens
    # once per scan job, not once for every evidence file.
    try:
        compiled = compile_enabled(rule_ids)
    except Exception as exc:
        return {
            "files_scanned": 0,
            "matched_files": 0,
            "match_count": 0,
            "results": [],
            "errors": [{"path": "<rule-catalog>", "error": str(exc)}],
            "catalog": catalog_summary(),
        }
    for path in paths[:1_000]:
        try:
            results.append(_scan_file_with_bundle(path, compiled))
        except Exception as exc:  # preserve per-file failure
            errors.append({"path": str(path), "error": str(exc)})
    return {
        "files_scanned": len(results),
        "matched_files": sum(bool(item.get("matches")) for item in results),
        "match_count": sum(len(item.get("matches", [])) for item in results),
        "results": results,
        "errors": errors,
        "catalog": catalog_summary(),
    }
