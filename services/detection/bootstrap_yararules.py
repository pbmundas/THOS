#!/usr/bin/env python3
"""Populate the Compose Yara-Rules/rules volume from vendor or pinned Git."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

from services.detection.fetch_yararules import DEFAULT_PINNED_REF, RULE_SUFFIXES


def count_rule_files(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(
        candidate.is_file() and candidate.suffix.lower() in RULE_SUFFIXES
        for candidate in path.rglob("*")
    )


def _version(path: Path) -> str:
    try:
        return (path / "VERSION.txt").read_text(encoding="utf-8")
    except OSError:
        return ""


def _clear(path: Path) -> None:
    resolved = path.resolve()
    if resolved.parent == resolved:
        raise RuntimeError(f"refusing to clear filesystem root: {resolved}")
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _copy(source: Path, destination: Path) -> None:
    _clear(destination)
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target)
        else:
            shutil.copy2(child, target)


def ensure_rules(
    vendor: Path,
    destination: Path,
    minimum: int,
    ref: str,
    fetch_script: Path,
) -> str:
    vendor_count = count_rule_files(vendor)
    existing_count = count_rule_files(destination)
    if vendor_count >= minimum:
        if existing_count == vendor_count and _version(destination) == _version(vendor):
            print(f"[yararules-init] reusing {existing_count} vendored rule files")
            return "volume"
        _copy(vendor, destination)
        print(f"[yararules-init] copied {count_rule_files(destination)} vendored rule files")
        return "vendor"
    if existing_count >= minimum and ref in _version(destination):
        print(f"[yararules-init] reusing {existing_count} pinned rule files")
        return "volume"

    print(
        f"[yararules-init] fetching pinned ref {ref}; "
        f"vendor={vendor_count}, volume={existing_count}"
    )
    subprocess.run(
        [sys.executable, str(fetch_script), "--ref", ref, "--dest", str(destination)],
        check=True,
    )
    ready_count = count_rule_files(destination)
    if ready_count < minimum:
        raise RuntimeError(
            f"download produced {ready_count} rule files; at least {minimum} are required"
        )
    print(f"[yararules-init] ready: {ready_count} community rule files")
    return "download"


def main() -> int:
    vendor = Path(os.getenv("YARARULES_VENDOR_DIR", "/vendor"))
    destination = Path(os.getenv("YARARULES_RULES_DIR", "/rules"))
    ref = os.getenv("YARARULES_REF", DEFAULT_PINNED_REF).strip() or DEFAULT_PINNED_REF
    fetch_script = Path(os.getenv(
        "YARARULES_FETCH_SCRIPT",
        "/repo/services/detection/fetch_yararules.py",
    ))
    try:
        minimum = int(os.getenv("YARARULES_MIN_FILES", "500"))
        if minimum < 1:
            raise ValueError
        ensure_rules(vendor, destination, minimum, ref, fetch_script)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[yararules-init] FATAL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
