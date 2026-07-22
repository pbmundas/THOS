"""Fail-fast verifier for services that execute or list SigmaHQ rules."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from services.detection.bootstrap_sigmahq_rules import count_rules


def verify_rules(path: Path, minimum: int, expected_ref: str = "") -> int:
    count = count_rules(path)
    if count < minimum:
        raise RuntimeError(
            f"SigmaHQ corpus invariant failed: {count} rule files found in {path}; "
            f"at least {minimum} are required"
        )
    marker = path / "VERSION.txt"
    version = marker.read_text(encoding="utf-8", errors="replace") if marker.is_file() else ""
    if expected_ref and expected_ref not in version:
        raise RuntimeError(
            f"SigmaHQ VERSION.txt in {path} does not contain pinned ref {expected_ref}"
        )
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    path = Path(os.environ.get("SIGMAHQ_RULES_DIR", "/repo/services/detection/sigma_rules_hq"))
    minimum = int(os.environ.get("SIGMAHQ_MIN_RULES", "2000"))
    expected_ref = os.environ.get("SIGMAHQ_REF", "").strip()
    try:
        count = verify_rules(path, minimum, expected_ref)
    except (OSError, RuntimeError, ValueError) as exc:
        if not args.quiet:
            print(f"[sigmahq-verify] FATAL: {exc}")
        return 1
    if not args.quiet:
        print(f"[sigmahq-verify] ready: {count} rules in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
