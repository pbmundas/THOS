import json

from services.siem.file_log_parser import parse_file


def test_unknown_binary_file_is_represented_as_bounded_artifact(tmp_path):
    path = tmp_path / "evidence.custom"
    path.write_bytes(b"\x7fELF\x00\x00suspicious printable string\x00" + b"x" * 32)

    records = parse_file(str(path))

    assert len(records) == 1
    assert records[0]["source_type"] == "artifact"
    assert records[0]["event"] == "artifact:.custom"
    detail = json.loads(records[0]["detail"])
    assert detail["size_bytes"] == path.stat().st_size
    assert detail["magic_hex"].startswith("7f454c46")
    assert detail["analysis_scope"].startswith("bounded artifact triage")
