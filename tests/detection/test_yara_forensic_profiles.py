from services.detection import yara_engine


class _Bundle:
    def __init__(self):
        self.timeout = None

    def match(self, *, filepath, timeout):
        self.timeout = timeout
        return []


def test_scan_file_accepts_bounded_memory_profile_overrides(tmp_path, monkeypatch):
    sample = tmp_path / "host.raw"
    sample.write_bytes(b"memory image")
    bundle = _Bundle()
    monkeypatch.setattr(yara_engine, "compile_enabled", lambda _rules=None: bundle)

    result = yara_engine.scan_file(
        sample,
        max_file_bytes=1024,
        timeout_seconds=600,
    )

    assert result["status"] == "clean"
    assert result["sha256"]
    assert bundle.timeout == 600


def test_scan_file_skips_artifact_above_selected_profile_limit(tmp_path, monkeypatch):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"12345")
    monkeypatch.setattr(yara_engine, "compile_enabled", lambda _rules=None: _Bundle())

    result = yara_engine.scan_file(sample, max_file_bytes=4)

    assert result["status"] == "skipped"
    assert "configured scan limit" in result["error"]
