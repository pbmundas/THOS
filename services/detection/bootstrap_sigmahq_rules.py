#!/usr/bin/env python3
"""Populate the Compose SigmaHQ volume from vendored rules or a pinned ref."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


DEFAULT_PINNED_REF = "282369fa76c5cd6103b055478fbaebec8530cfa5"
RULE_SUFFIXES = {".yml", ".yaml"}


def count_rules(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(
        1
        for candidate in path.rglob("*")
        if candidate.is_file() and candidate.suffix.lower() in RULE_SUFFIXES
    )


def _version(path: Path) -> str:
    marker = path / "VERSION.txt"
    try:
        return marker.read_text(encoding="utf-8")
    except OSError:
        return ""


def _matches_ref(path: Path, ref: str) -> bool:
    """Require traceability before trusting a persistent downloaded corpus."""
    return bool(ref and ref in _version(path))


def _clear_directory(path: Path) -> None:
    resolved = path.resolve()
    if resolved.parent == resolved:
        raise RuntimeError(f"refusing to clear filesystem root: {resolved}")
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _copy_directory(source: Path, target: Path) -> None:
    _clear_directory(target)
    for child in source.iterdir():
        destination = target / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, destination)
        else:
            shutil.copy2(child, destination)


def ensure_rules(
    vendor_dir: Path,
    target_dir: Path,
    minimum_rules: int,
    ref: str,
    fetch_script: Path,
) -> str:
    """Ensure target has a complete rules corpus; return its source."""
    vendored_count = count_rules(vendor_dir)
    target_count = count_rules(target_dir)

    if vendored_count >= minimum_rules:
        if target_count == vendored_count and _version(target_dir) == _version(vendor_dir):
            print(f"[sigmahq-rules-init] reusing {target_count} vendored rules in volume")
            return "volume"
        _copy_directory(vendor_dir, target_dir)
        copied_count = count_rules(target_dir)
        if copied_count < minimum_rules:
            raise RuntimeError(
                f"vendored copy produced only {copied_count} rules; expected at least {minimum_rules}"
            )
        print(f"[sigmahq-rules-init] copied {copied_count} vendored rules into volume")
        return "vendor"

    if target_count >= minimum_rules and _matches_ref(target_dir, ref):
        print(f"[sigmahq-rules-init] reusing {target_count} previously downloaded rules")
        return "volume"

    if target_count >= minimum_rules:
        print(
            f"[sigmahq-rules-init] existing {target_count}-rule corpus does not match "
            f"requested ref {ref}; refreshing"
        )

    print(
        f"[sigmahq-rules-init] no complete local corpus found "
        f"(vendor={vendored_count}, volume={target_count}); fetching pinned ref {ref}"
    )
    subprocess.run(
        [sys.executable, str(fetch_script), "--ref", ref, "--dest", str(target_dir)],
        check=True,
    )
    downloaded_count = count_rules(target_dir)
    if downloaded_count < minimum_rules:
        raise RuntimeError(
            f"download produced only {downloaded_count} rules; expected at least {minimum_rules}"
        )
    print(f"[sigmahq-rules-init] ready: {downloaded_count} SigmaHQ rules")
    return "download"


def main() -> int:
    vendor_dir = Path(os.getenv("SIGMAHQ_VENDOR_DIR", "/vendor"))
    target_dir = Path(os.getenv("SIGMAHQ_RULES_DIR", "/rules"))
    ref = os.getenv("SIGMAHQ_REF", DEFAULT_PINNED_REF).strip() or DEFAULT_PINNED_REF
    fetch_script = Path(
        os.getenv(
            "SIGMAHQ_FETCH_SCRIPT",
            "/repo/services/detection/fetch_sigmahq_rules.py",
        )
    )
    try:
        minimum_rules = int(os.getenv("SIGMAHQ_MIN_RULES", "2000"))
        if minimum_rules < 1:
            raise ValueError
    except ValueError:
        print("[sigmahq-rules-init] FATAL: SIGMAHQ_MIN_RULES must be a positive integer", file=sys.stderr)
        return 2

    try:
        ensure_rules(vendor_dir, target_dir, minimum_rules, ref, fetch_script)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[sigmahq-rules-init] FATAL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
