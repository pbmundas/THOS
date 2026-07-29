"""Health verifier for the managed community YARA corpus and catalog."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from services.detection.bootstrap_yararules import count_rule_files
from services.detection.yara_catalog import load_catalog


def verify() -> tuple[int, int]:
    rules_dir = Path(os.getenv("YARARULES_RULES_DIR", "/data/yara-community"))
    minimum_files = int(os.getenv("YARARULES_MIN_FILES", "500"))
    files = count_rule_files(rules_dir)
    if files < minimum_files:
        raise RuntimeError(
            f"community YARA corpus has {files} files; {minimum_files} required"
        )
    catalog = load_catalog()
    minimum_ready = int(os.getenv("YARARULES_MIN_READY_RULES", "500"))
    ready = int(catalog.get("ready_rules", 0))
    if ready < minimum_ready:
        raise RuntimeError(
            f"community YARA catalog has {ready} ready rules; {minimum_ready} required"
        )
    import yara
    catalog_dir = Path(os.getenv("YARA_CATALOG_DIR", "/data/yara-catalog"))
    yara.load(str(catalog_dir / "community.compiled"))
    yara.load(str(catalog_dir / "community-actionable.compiled"))
    return files, ready


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        files, ready = verify()
    except (OSError, RuntimeError, ValueError) as exc:
        if not args.quiet:
            print(f"[yara-catalog-verify] FATAL: {exc}")
        return 1
    if not args.quiet:
        print(f"[yara-catalog-verify] ready: {ready} rules from {files} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
