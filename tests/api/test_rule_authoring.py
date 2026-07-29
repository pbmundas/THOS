import pytest
from fastapi import HTTPException

from services.api import control_plane


def test_detection_rule_authoring_normalizes_and_preserves_id():
    rule_id, content = control_plane._validated_detection_rule(
        """
title: Suspicious example execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\example.exe'
  condition: selection
level: high
"""
    )

    assert rule_id
    assert f"id: {rule_id}" in content
    assert "level: high" in content
    assert "status: experimental" in content

    with pytest.raises(HTTPException):
        control_plane._validated_detection_rule(content, expected_id="different-id")


def test_detection_rule_authoring_rejects_missing_condition():
    with pytest.raises(HTTPException, match="condition"):
        control_plane._validated_detection_rule(
            """
title: Incomplete rule
logsource:
  category: process_creation
detection:
  selection:
    Image: example.exe
"""
        )


def test_yara_rule_authoring_compiles_and_preserves_name():
    source = """
rule Managed_Test_Rule {
  strings:
    $a = "managed-test"
  condition:
    $a
}
"""
    rule_id, normalized = control_plane._validated_yara_rule(source)

    assert rule_id == "Managed_Test_Rule"
    assert "rule Managed_Test_Rule" in normalized

    with pytest.raises(HTTPException):
        control_plane._validated_yara_rule(source, expected_id="Other_Rule")


def test_yara_rule_authoring_rejects_multiple_public_rules():
    with pytest.raises(HTTPException, match="exactly one"):
        control_plane._validated_yara_rule(
            "rule One { condition: true }\nrule Two { condition: true }\n"
        )
