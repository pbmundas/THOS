from pathlib import Path
import subprocess

import pytest

from services.detection.bootstrap_sigmahq_rules import count_rules, ensure_rules


def _write_corpus(path: Path, count: int, version: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "VERSION.txt").write_text(version, encoding="utf-8")
    for index in range(count):
        rule = path / "rules" / f"rule-{index}.yml"
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text(f"title: Rule {index}\nid: {index}\n", encoding="utf-8")


def test_complete_vendored_corpus_is_copied_without_fetch(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    target = tmp_path / "target"
    _write_corpus(vendor, 3, "Commit: reviewed")

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError("network fetch must not run when vendored rules are complete")

    monkeypatch.setattr(subprocess, "run", unexpected_fetch)

    source = ensure_rules(vendor, target, 3, "pinned", tmp_path / "fetch.py")

    assert source == "vendor"
    assert count_rules(target) == 3
    assert (target / "VERSION.txt").read_text(encoding="utf-8") == "Commit: reviewed"


def test_matching_persistent_corpus_is_reused_without_fetch(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    target = tmp_path / "target"
    _write_corpus(target, 3, "Commit: pinned-commit")

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError("matching persistent rules must be reused")

    monkeypatch.setattr(subprocess, "run", unexpected_fetch)

    source = ensure_rules(vendor, target, 3, "pinned-commit", tmp_path / "fetch.py")

    assert source == "volume"
    assert count_rules(target) == 3


def test_missing_corpus_fetches_requested_ref_and_validates_count(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    target = tmp_path / "target"
    calls = []

    def fake_fetch(command, check):
        calls.append((command, check))
        _write_corpus(target, 3, "Commit: pinned-commit")

    monkeypatch.setattr(subprocess, "run", fake_fetch)

    source = ensure_rules(vendor, target, 3, "pinned-commit", tmp_path / "fetch.py")

    assert source == "download"
    assert calls[0][0][-4:] == ["--ref", "pinned-commit", "--dest", str(target)]
    assert calls[0][1] is True


def test_download_below_minimum_fails_closed(tmp_path, monkeypatch):
    target = tmp_path / "target"

    def incomplete_fetch(command, check):
        _write_corpus(target, 1, "Commit: pinned-commit")

    monkeypatch.setattr(subprocess, "run", incomplete_fetch)

    with pytest.raises(RuntimeError, match="expected at least 3"):
        ensure_rules(tmp_path / "vendor", target, 3, "pinned-commit", tmp_path / "fetch.py")
