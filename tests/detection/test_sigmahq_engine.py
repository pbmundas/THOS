"""
Unit tests for services.detection.sigmahq_engine.

These deliberately use small, synthetic Sigma rules written to a tmp_path
rather than the vendored services/detection/sigma_rules_hq/ corpus, so
they pass regardless of whether that directory has been populated by
fetch_sigmahq_rules.py yet, and so a single test failure points at a
specific piece of Sigma grammar rather than "some rule somewhere in
2,800+ files broke".

Requires the `pysigma` package (see requirements.txt). Skipped, not
failed, if it isn't installed.
"""
import pytest

sigma = pytest.importorskip("sigma", reason="pysigma not installed")

from services.detection import sigmahq_engine  # noqa: E402


def _write_rule(tmp_path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _clear_cache():
    # load_rules() caches per rules_dir; each test writes to a fresh
    # tmp_path so collisions shouldn't happen, but clear defensively
    # since lru_cache is process-global.
    sigmahq_engine.clear_cache()
    yield
    sigmahq_engine.clear_cache()


SIMPLE_RULE = """\
title: Suspicious LSASS Access
id: test-0001
status: test
logsource:
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
    condition: selection
level: high
tags:
    - attack.credential_access
"""

AND_OR_RULE = """\
title: Encoded PowerShell Download
id: test-0002
status: test
logsource:
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
    condition: selection_img and selection_cli
level: medium
"""

NOT_RULE = """\
title: Rundll32 Without Signed DLL
id: test-0003
status: test
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
    filter:
        CommandLine|contains: 'signed_ok.dll'
    condition: selection and not filter
level: medium
"""

REGEX_RULE = """\
title: Suspicious User-Agent Regex
id: test-0004
status: test
logsource:
    category: proxy
detection:
    selection:
        c-useragent|re: '^[a-z]{2}\\d{6}$'
    condition: selection
level: low
"""


def test_simple_field_match_and_no_match(tmp_path):
    _write_rule(tmp_path, "simple.yml", SIMPLE_RULE)
    rules = sigmahq_engine.load_rules(str(tmp_path))
    assert len(rules) == 1

    matching_record = {
        "timestamp": "2026-07-10T00:00:00Z",
        "host": "WIN-DC01",
        "user": "asmith",
        "event": "10",
        "detail": "ProcessAccess: TargetImage=C:\\Windows\\System32\\lsass.exe SourceImage=mimikatz.exe",
    }
    non_matching_record = {
        "timestamp": "2026-07-10T00:00:01Z",
        "host": "WIN-DC01",
        "user": "asmith",
        "event": "1",
        "detail": "ProcessCreate: notepad.exe",
    }

    result = sigmahq_engine.evaluate_all([matching_record, non_matching_record], rules=rules)
    assert result["rules_evaluated"] == 1
    assert result["matched_record_indices"] == [0]
    assert result["rule_matches"][0]["rule_id"] == "test-0001"
    assert result["rule_matches"][0]["title"] == "Suspicious LSASS Access"
    assert result["rule_matches"][0]["level"] == "high"
    assert "attack.credential_access" in result["rule_matches"][0]["tags"]


def test_and_condition_requires_both_selections(tmp_path):
    _write_rule(tmp_path, "and_or.yml", AND_OR_RULE)
    rules = sigmahq_engine.load_rules(str(tmp_path))

    both = {"detail": "ProcessCreate: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                       "CommandLine=powershell.exe -enc SQBFAFgA"}
    only_image = {"detail": "ProcessCreate: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                             "CommandLine=powershell.exe -File script.ps1"}
    only_cli = {"detail": "ProcessCreate: Image=cmd.exe CommandLine=cmd.exe -enc foo"}

    result = sigmahq_engine.evaluate_all([both, only_image, only_cli], rules=rules)
    assert result["matched_record_indices"] == [0]


def test_and_not_condition_excludes_filtered_records(tmp_path):
    _write_rule(tmp_path, "not_rule.yml", NOT_RULE)
    rules = sigmahq_engine.load_rules(str(tmp_path))

    suspicious = {"detail": "ProcessCreate: Image=C:\\Windows\\System32\\rundll32.exe CommandLine=rundll32.exe evil.dll,Entry"}
    filtered_out = {"detail": "ProcessCreate: Image=C:\\Windows\\System32\\rundll32.exe CommandLine=rundll32.exe signed_ok.dll,Entry"}

    result = sigmahq_engine.evaluate_all([suspicious, filtered_out], rules=rules)
    assert result["matched_record_indices"] == [0]


def test_regex_modifier(tmp_path):
    _write_rule(tmp_path, "regex.yml", REGEX_RULE)
    rules = sigmahq_engine.load_rules(str(tmp_path))

    matching = {"detail": "proxy log c-useragent=ab123456 other=fields"}
    non_matching = {"detail": "proxy log c-useragent=Mozilla/5.0 other=fields"}

    result = sigmahq_engine.evaluate_all([matching, non_matching], rules=rules)
    assert result["matched_record_indices"] == [0]


def test_field_mapping_uses_normalized_schema_fields(tmp_path):
    """EventID/User/ComputerName should map onto THOS's normalized
    event/user/host fields rather than falling back to `detail`."""
    _write_rule(tmp_path, "mapped.yml", """\
title: Failed Logon For Specific User
id: test-0005
status: test
logsource:
    category: authentication
detection:
    selection:
        EventID: 4625
        User: 'svc_backup'
    condition: selection
level: medium
""")
    rules = sigmahq_engine.load_rules(str(tmp_path))

    record = {"event": "4625", "user": "svc_backup", "detail": "logon failure"}
    other_user = {"event": "4625", "user": "jdoe", "detail": "logon failure"}

    result = sigmahq_engine.evaluate_all([record, other_user], rules=rules)
    assert result["matched_record_indices"] == [0]


def test_malformed_rule_file_does_not_abort_load(tmp_path):
    _write_rule(tmp_path, "good.yml", SIMPLE_RULE)
    _write_rule(tmp_path, "broken.yml", "this: [is not, valid sigma")

    rules = sigmahq_engine.load_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0].rule_id == "test-0001"


def test_evaluate_all_with_no_rules_returns_empty_result():
    result = sigmahq_engine.evaluate_all([{"detail": "anything"}], rules=[])
    assert result == {
        "matched_record_indices": [],
        "rule_matches": [],
        "rules_evaluated": 0,
    }


def test_load_rules_is_cached_per_directory(tmp_path):
    _write_rule(tmp_path, "simple.yml", SIMPLE_RULE)
    first = sigmahq_engine.load_rules(str(tmp_path))
    second = sigmahq_engine.load_rules(str(tmp_path))
    assert [r.rule_id for r in first] == [r.rule_id for r in second]

    sigmahq_engine.clear_cache()
    _write_rule(tmp_path, "and_or.yml", AND_OR_RULE)
    third = sigmahq_engine.load_rules(str(tmp_path))
    assert len(third) == 2
