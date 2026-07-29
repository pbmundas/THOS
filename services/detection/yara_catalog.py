"""Build a reusable, isolated Yara-Rules/rules compiled catalog."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any


CATALOG_VERSION = 3
RULES_DIR = Path(os.getenv("YARARULES_RULES_DIR", "/rules"))
CATALOG_DIR = Path(os.getenv("YARA_CATALOG_DIR", "/catalog"))
MIN_FILES = int(os.getenv("YARARULES_MIN_FILES", "500"))
RULE_SUFFIXES = {".yar", ".yara"}
EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
}
RULE_HEADER = re.compile(
    r"(?m)^\s*(?P<modifiers>(?:(?:private|global)\s+)*)rule\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]+)?\{"
)


def _default_excluded_categories() -> set[str]:
    return {
        item.strip().lower()
        for item in os.getenv(
            "YARA_DEFAULT_EXCLUDED_CATEGORIES",
            "utils,crypto,deprecated",
        ).split(",")
        if item.strip()
    }


def _yara():
    import yara
    return yara


def _files() -> list[Path]:
    return sorted(
        candidate for candidate in RULES_DIR.rglob("*")
        if candidate.is_file() and candidate.suffix.lower() in RULE_SUFFIXES
    )


def _blocks(text: str) -> list[tuple[str, str, set[str]]]:
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


def _meta(block: str, names: tuple[str, ...]) -> str:
    for name in names:
        match = re.search(
            rf"(?m)^\s*{re.escape(name)}\s*=\s*(?:\"([^\"]*)\"|([0-9]+))",
            block,
        )
        if match:
            return match.group(1) or match.group(2) or ""
    return ""


def _severity(block: str) -> str:
    value = _meta(block, ("severity", "level", "threat_level")).lower()
    aliases = {
        "info": "informational", "informational": "informational",
        "low": "low", "medium": "medium", "moderate": "medium",
        "high": "high", "critical": "critical", "severe": "critical",
    }
    if value in aliases:
        return aliases[value]
    score = _meta(block, ("score", "threat_score"))
    if score.isdigit():
        number = int(score)
        if number >= 90:
            return "critical"
        if number >= 70:
            return "high"
        if number < 30:
            return "low"
    return "medium"


def _namespace(relative: str) -> str:
    return f"community_{hashlib.sha256(relative.encode('utf-8')).hexdigest()[:20]}"


def _entry(
    relative: str,
    namespace: str,
    name: str,
    block: str,
    modifiers: set[str],
    status: str,
    error: str = "",
) -> dict[str, Any]:
    category = relative.split("/", 1)[0] if "/" in relative else "root"
    catalog_id = f"community:{relative}:{name}"
    return {
        "id": catalog_id,
        "rule_name": name,
        "title": _meta(block, ("title", "description")) or name.replace("_", " "),
        "description": _meta(block, ("description", "reference")),
        "severity": _severity(block),
        "status": "deprecated" if relative.startswith("deprecated/") else (
            _meta(block, ("status",)) or "community"
        ),
        "attack": _meta(block, ("attack", "mitre_attack", "technique")),
        "source": "Yara-Rules/rules",
        "category": category,
        "relative_path": relative,
        "namespace": namespace,
        "modifiers": sorted(modifiers),
        "private": "private" in modifiers,
        "compilation_status": status,
        "compilation_error": error,
    }


def _source_hash(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(RULES_DIR).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_catalog() -> dict[str, Any]:
    yara = _yara()
    files = _files()
    if len(files) < MIN_FILES:
        raise RuntimeError(
            f"Yara-Rules corpus invariant failed: {len(files)} files found; "
            f"at least {MIN_FILES} required"
        )
    source_hash = _source_hash(files)
    target_manifest = CATALOG_DIR / "catalog.json"
    target_compiled = CATALOG_DIR / "community.compiled"
    target_actionable = CATALOG_DIR / "community-actionable.compiled"
    if (
        target_manifest.is_file()
        and target_compiled.is_file()
        and target_actionable.is_file()
    ):
        try:
            existing = json.loads(target_manifest.read_text(encoding="utf-8"))
            if (
                existing.get("version") == CATALOG_VERSION
                and existing.get("source_hash") == source_hash
            ):
                yara.load(str(target_compiled))
                print(
                    f"[yara-catalog-init] reusing {existing.get('ready_rules', 0)} "
                    "compiled community rules"
                )
                return existing
        except (OSError, ValueError):
            pass

    ready_sources: dict[str, str] = {}
    source_categories: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    aggregate_only = 0
    private_rules = 0
    common_helpers = ""
    common_path = RULES_DIR / "malware" / "000_common_rules.yar"
    if common_path.is_file():
        common_helpers = common_path.read_text(encoding="utf-8", errors="replace")
    for path in files:
        relative = path.relative_to(RULES_DIR).as_posix()
        namespace = _namespace(relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        blocks = _blocks(text)
        if not blocks:
            aggregate_only += 1
            continue
        try:
            yara.compile(source=text, externals=EXTERNALS)
            status, error = "ready", ""
            ready_sources[namespace] = text
            source_categories[namespace] = (
                relative.split("/", 1)[0].lower()
                if "/" in relative
                else "root"
            )
        except Exception as exc:  # isolate incompatible community files
            initial_error = str(exc)[:1000]
            # A small set of upstream ELF signatures depends on the private
            # is__elf helper from malware/000_common_rules.yar. Preserve that
            # dependency inside the file's namespace instead of discarding
            # otherwise valid signatures.
            if (
                common_helpers
                and path != common_path
                and 'undefined identifier "is__elf"' in initial_error
            ):
                try:
                    source = f"{common_helpers}\n\n{text}"
                    yara.compile(source=source, externals=EXTERNALS)
                    status, error = "ready", ""
                    ready_sources[namespace] = source
                    source_categories[namespace] = (
                        relative.split("/", 1)[0].lower()
                        if "/" in relative
                        else "root"
                    )
                except Exception as fallback_exc:
                    status, error = "invalid", str(fallback_exc)[:1000]
            else:
                status, error = "invalid", initial_error
            if status != "ready":
                failures.append({"path": relative, "error": error})
        for name, block, modifiers in blocks:
            if "private" in modifiers:
                private_rules += 1
            entries.append(_entry(
                relative, namespace, name, block, modifiers, status, error
            ))

    if not ready_sources:
        raise RuntimeError("no community YARA files compiled successfully")
    compiled = yara.compile(sources=ready_sources, externals=EXTERNALS)
    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=CATALOG_DIR, delete=False) as handle:
        temporary_compiled = Path(handle.name)
    compiled.save(str(temporary_compiled))
    temporary_compiled.replace(target_compiled)
    excluded_categories = _default_excluded_categories()
    actionable_sources = {
        namespace: source
        for namespace, source in ready_sources.items()
        if source_categories.get(namespace, "root") not in excluded_categories
    }
    if not actionable_sources:
        raise RuntimeError("default actionable YARA corpus is empty")
    actionable_compiled = yara.compile(
        sources=actionable_sources,
        externals=EXTERNALS,
    )
    with tempfile.NamedTemporaryFile(dir=CATALOG_DIR, delete=False) as handle:
        temporary_actionable = Path(handle.name)
    actionable_compiled.save(str(temporary_actionable))
    temporary_actionable.replace(target_actionable)

    version_text = ""
    try:
        version_text = (RULES_DIR / "VERSION.txt").read_text(encoding="utf-8")
    except OSError:
        pass
    public_entries = [item for item in entries if not item["private"]]
    payload = {
        "version": CATALOG_VERSION,
        "source": "https://github.com/Yara-Rules/rules",
        "source_version": version_text,
        "source_hash": source_hash,
        "rule_files": len(files),
        "aggregate_files": aggregate_only,
        "ready_files": len(ready_sources),
        "invalid_files": len(failures),
        "rule_definitions": len(entries),
        "private_rules": private_rules,
        "ready_rules": sum(
            item["compilation_status"] == "ready" for item in public_entries
        ),
        "actionable_rules": sum(
            item["compilation_status"] == "ready"
            and str(item.get("category", "")).lower() not in excluded_categories
            for item in public_entries
        ),
        "default_excluded_categories": sorted(excluded_categories),
        "invalid_rules": sum(
            item["compilation_status"] != "ready" for item in public_entries
        ),
        "compiled_at": datetime.now(timezone.utc).isoformat(),
        "entries": public_entries,
        "failures": failures,
    }
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=CATALOG_DIR, delete=False
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        temporary_manifest = Path(handle.name)
    temporary_manifest.replace(target_manifest)
    print(
        f"[yara-catalog-init] files={len(files)}, ready_files={len(ready_sources)}, "
        f"invalid_files={len(failures)}, ready_rules={payload['ready_rules']}, "
        f"invalid_rules={payload['invalid_rules']}"
    )
    return payload


def load_catalog() -> dict[str, Any]:
    target = CATALOG_DIR / "catalog.json"
    if not target.is_file():
        raise RuntimeError(
            f"YARA catalog is missing at {target}; Compose must complete yara-catalog-init"
        )
    return json.loads(target.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "verify"), nargs="?", default="build")
    args = parser.parse_args()
    payload = build_catalog() if args.command == "build" else load_catalog()
    if args.command == "verify":
        _yara().load(str(CATALOG_DIR / "community.compiled"))
        _yara().load(str(CATALOG_DIR / "community-actionable.compiled"))
        print(
            f"[yara-catalog-init] verified {payload.get('ready_rules', 0)} "
            "compiled community rules"
        )
    return 0 if payload.get("ready_rules", 0) > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
