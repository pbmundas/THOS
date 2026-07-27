#!/usr/bin/env python3
"""Fetch a pinned Yara-Rules/rules corpus for the Compose initializer."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO_URL = "https://github.com/Yara-Rules/rules.git"
DEFAULT_PINNED_REF = "0f93570194a80d2f2032869055808b0ddcdfb360"
RULE_SUFFIXES = {".yar", ".yara"}


def _run(command: list[str], **kwargs) -> None:
    subprocess.run(command, check=True, **kwargs)


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


def fetch(ref: str, destination: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="thos-yararules-") as temporary:
        checkout = Path(temporary) / "checkout"
        _run([
            "git", "clone", "--filter=blob:none", "--no-checkout",
            REPO_URL, str(checkout),
        ])
        _run(["git", "-C", str(checkout), "checkout", "--detach", ref])
        commit = subprocess.check_output(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            text=True,
        ).strip()

        staged = Path(temporary) / "staged"
        staged.mkdir()
        count = 0
        for source in checkout.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(checkout)
            if ".git" in relative.parts:
                continue
            if source.suffix.lower() not in RULE_SUFFIXES and relative.as_posix() not in {
                "LICENSE", "README.md",
            }:
                continue
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if source.suffix.lower() in RULE_SUFFIXES:
                count += 1

        (staged / "VERSION.txt").write_text(
            "\n".join([
                "Yara-Rules/rules managed corpus",
                "================================",
                "",
                "Source: https://github.com/Yara-Rules/rules",
                f"Commit: {commit} (requested ref: {ref})",
                f"Fetched: {datetime.now(timezone.utc).isoformat()}",
                f"Rule files: {count}",
                "License: GNU GPL v2; see LICENSE in this directory.",
                "",
            ]),
            encoding="utf-8",
        )

        destination.parent.mkdir(parents=True, exist_ok=True)
        _clear_directory(destination)
        for child in staged.iterdir():
            target = destination / child.name
            if child.is_dir() and not child.is_symlink():
                shutil.copytree(child, target)
            else:
                shutil.copy2(child, target)
        return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default=DEFAULT_PINNED_REF)
    parser.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args()
    count = fetch(args.ref, args.dest)
    print(f"[yararules-fetch] copied {count} rule files at {args.ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
