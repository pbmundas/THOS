import json

from services.hunting.query_generator import (
    _fallback_query,
    _normalize_folder_query,
    _normalize_wazuh_query,
    validate_and_normalize_query,
)


def test_wazuh_fallback_is_valid_query_dsl():
    query = _fallback_query("Suspicious Nmap reconnaissance activity", "wazuh")
    payload = json.loads(query)

    assert "query" in payload
    assert payload["query"]["simple_query_string"]["default_operator"] == "or"
    assert "data.*" not in payload["query"]["simple_query_string"]["fields"]


def test_wazuh_fallback_keeps_concrete_h111_indicator():
    query = _fallback_query(
        "An adversary is performing network service discovery by deploying "
        "port scanning tools such as Advanced IP Scanner, SoftPerfect Network "
        "Scanner, or nmap to identify accessible services",
        "wazuh",
    )

    search = json.loads(query)["query"]["simple_query_string"]["query"]

    assert "nmap" in search.split()
    assert "adversary" not in search.split()


def test_wazuh_normalizer_discards_model_control_of_size_and_sort():
    candidate = json.dumps({
        "size": 50000,
        "sort": [{"rule.level": "asc"}],
        "query": {"match": {"rule.groups": "purple_team"}},
    })
    payload = json.loads(_normalize_wazuh_query(candidate, "reconnaissance"))

    assert payload == {"query": {"match": {"rule.groups": "purple_team"}}}


def test_wazuh_normalizer_falls_back_on_non_json_model_output():
    query = _normalize_wazuh_query("Here is your query: ...", "Nmap scan")
    assert "simple_query_string" in json.loads(query)["query"]


def test_wazuh_normalizer_falls_back_on_model_range():
    candidate = '{"query":{"range":{"@timestamp":{"gte":"adversary"}}}}'

    query = _normalize_wazuh_query(candidate, "Nmap scan")

    assert "simple_query_string" in json.loads(query)["query"]


def test_wazuh_normalizer_falls_back_on_wildcard_fields():
    candidate = json.dumps({
        "query": {
            "simple_query_string": {
                "query": "nmap",
                "fields": ["data.*"],
            }
        }
    })

    query = _normalize_wazuh_query(candidate, "Nmap scan")

    assert "data.*" not in json.loads(query)["query"]["simple_query_string"]["fields"]


def test_qradar_invalid_model_output_retries_with_valid_read_only_aql():
    result = validate_and_normalize_query(
        "WHERE Process Name = 'powershell.exe'", "PowerShell execution", "qradar"
    )

    assert result["query"] == "SELECT * FROM events"
    assert result["used_fallback"] is True
    assert "complete SELECT" in result["validation_error"]


def test_splunk_state_changing_command_is_never_executed():
    result = validate_and_normalize_query(
        "index=main | delete", "Suspicious PowerShell", "splunk"
    )

    assert result["query"] == "*"
    assert "delete" not in result["query"]
    assert result["used_fallback"] is True


def test_folder_query_removes_generic_prose_and_keeps_explicit_indicators():
    result = _normalize_folder_query(
        "often, utilize, powershell, powerful, language, available, windows",
        "Detect powershell.exe activity using Event ID 4104",
    )

    assert result == "powershell, 4104, powershell.exe"
