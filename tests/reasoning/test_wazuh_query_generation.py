import json

from services.hunting.query_generator import (
    _normalize_folder_query,
    _normalize_wazuh_query,
    validate_and_normalize_query,
)


def test_wazuh_normalizer_removes_model_control_of_size_and_sort():
    candidate = json.dumps({
        "size": 50000,
        "sort": [{"rule.level": "asc"}],
        "query": {"match": {"rule.groups": "purple_team"}},
    })
    payload = json.loads(_normalize_wazuh_query(candidate))

    assert payload == {"query": {"match": {"rule.groups": "purple_team"}}}


def test_invalid_wazuh_model_output_is_not_replaced_with_a_fake_query():
    try:
        _normalize_wazuh_query("not JSON")
    except ValueError as exc:
        assert "valid JSON" in str(exc)
    else:
        raise AssertionError("invalid model output was accepted")


def test_wazuh_wildcard_field_is_rejected():
    candidate = json.dumps({
        "query": {
            "simple_query_string": {
                "query": "nmap",
                "fields": ["data.*"],
            }
        }
    })
    try:
        _normalize_wazuh_query(candidate)
    except ValueError as exc:
        assert "disallowed" in str(exc)
    else:
        raise AssertionError("wildcard field was accepted")


def test_qradar_incomplete_query_is_rejected_not_replaced():
    result = validate_and_normalize_query(
        "WHERE Process Name = 'powershell.exe'",
        "PowerShell execution",
        "qradar",
    )

    assert result["query"] == ""
    assert "complete SELECT" in result["validation_error"]


def test_splunk_state_changing_command_is_never_executed():
    result = validate_and_normalize_query(
        "index=main | delete", "Suspicious PowerShell", "splunk"
    )

    assert result["query"] == ""
    assert "state-changing" in result["validation_error"]


def test_folder_normalizer_keeps_agent_supplied_literal_tokens():
    result = _normalize_folder_query("powershell, 4104, powershell.exe")

    assert result == "powershell, 4104, powershell.exe"
