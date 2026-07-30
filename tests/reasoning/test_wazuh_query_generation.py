import json

from services.hunting.query_generator import (
    _compile_grounded_branch_query,
    _compile_wazuh_plan,
    _grounded_query_literals,
    _normalize_folder_query,
    _normalize_wazuh_query,
    _query_field_catalog,
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


def test_wazuh_normalizer_removes_model_range_but_keeps_evidence_clause():
    candidate = json.dumps({
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                ],
                "must": [
                    {"match_phrase": {"data.process.name": "scanner.exe"}},
                ],
            },
        },
    })

    result = validate_and_normalize_query(
        candidate,
        "Investigate process activity",
        "wazuh",
    )

    assert json.loads(result["query"]) == {
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"data.process.name": "scanner.exe"}},
                ],
            },
        },
    }
    assert result["validation_error"] is None


def test_wazuh_range_only_query_still_fails_closed():
    result = validate_and_normalize_query(
        json.dumps({
            "query": {
                "range": {"@timestamp": {"gte": "now-24h"}},
            },
        }),
        "Investigate process activity",
        "wazuh",
    )

    assert result["query"] == ""
    assert "requires an evidence clause" in result["validation_error"]


def test_wazuh_field_alternatives_are_expanded_from_catalog_data():
    catalog = _query_field_catalog({
        "process_name": "data.process.name / data.win.eventdata.image",
        "mitre_technique": "rule.mitre.id",
        "host": "agent.name",
        "available_fields": "rule.mitre.id, agent.name",
    })

    assert catalog == {
        "normalized_fields": {
            "mitre_technique": ["rule.mitre.id"],
            "host": ["agent.name"],
        },
        "allowed_fields": [
            "rule.mitre.id",
            "agent.name",
        ],
        "field_data_sources": {
            "rule.mitre.id": [],
            "agent.name": [],
        },
            "field_value_kinds": {
                "rule.mitre.id": [],
                "agent.name": [],
            },
            "field_query_priorities": {
                "rule.mitre.id": 50,
                "agent.name": 50,
            },
        }


def test_wazuh_query_rejects_fields_outside_data_driven_catalog():
    result = validate_and_normalize_query(
        json.dumps({
            "query": {
                "match_phrase": {"invented.process.field": "scanner.exe"},
            },
        }),
        "Investigate scanner execution",
        "wazuh",
        allowed_fields=["data.process.name"],
    )

    assert result["query"] == ""
    assert "outside allowed_fields" in result["validation_error"]


def test_wazuh_query_rejects_invented_values():
    result = validate_and_normalize_query(
        json.dumps({
            "query": {
                "bool": {
                    "must": [
                        {"match": {"data.process.pid": "12345"}},
                        {"match": {"data.process.state": "running"}},
                    ],
                },
            },
        }),
        "Investigate nmap.exe network service discovery",
        "wazuh",
        allowed_fields=["data.process.pid", "data.process.state"],
        grounding_text="Investigate nmap.exe network service discovery T1046",
    )

    assert result["query"] == ""
    assert "invented values" in result["validation_error"]
    assert "12345" in result["validation_error"]


def test_wazuh_query_accepts_values_from_governed_context():
    result = validate_and_normalize_query(
        json.dumps({
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"data.process.name": "nmap.exe"}},
                        {"term": {"data.dest_port": 3389}},
                    ],
                    "minimum_should_match": 1,
                },
            },
        }),
        "Investigate nmap.exe network service discovery on port 3389",
        "wazuh",
        allowed_fields=["data.process.name", "data.dest_port"],
        grounding_text=(
            "Investigate nmap.exe network service discovery on port 3389 "
            "under T1046"
        ),
    )

    assert result["query"]
    assert result["validation_error"] is None


def test_structured_wazuh_plan_compiles_only_catalog_fields_and_values():
    literals = _grounded_query_literals(
        "Investigate nmap.exe network service discovery on port 3389",
        "Retrieve scanner execution and network evidence",
        {"technique_id": "T1046"},
    )
    query = _compile_wazuh_plan(
        json.dumps({
            "clauses": [
                {
                    "field": "data.process.name",
                    "operator": "match_phrase",
                    "value": "nmap.exe",
                },
                {
                    "field": "data.dest_port",
                    "operator": "term",
                    "value": "3389",
                },
            ],
        }),
        ["data.process.name", "data.dest_port"],
        literals,
    )

    assert json.loads(query) == {
        "query": {
            "bool": {
                "should": [
                    {
                        "match_phrase": {
                            "data.process.name": "nmap.exe",
                        },
                    },
                    {"term": {"data.dest_port": "3389"}},
                ],
                "minimum_should_match": 1,
            },
        },
    }


def test_grounded_literals_exclude_generic_hypothesis_prose():
    literals = _grounded_query_literals(
        (
            "An adversary performs network service discovery with nmap.exe "
            "against port 3389 using TCP SYN packets."
        ),
        "Retrieve direct evidence.",
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "requirements": {
                "literal_observables": ["nmap.exe"],
                "investigation_steps": [
                    "Review all relevant records.",
                ],
            },
        },
    )

    assert "T1046" in literals
    assert "nmap.exe" in literals
    assert "3389" in literals
    assert "TCP" in literals
    assert "adversary" not in literals


def test_grounded_literals_exclude_supervisor_resource_controls():
    literals = _grounded_query_literals(
        "Investigate nmap.exe network discovery on port 3389.",
        (
            "Retrieve matching events from the last 14 days, limited to "
            "2000 results."
        ),
        {"technique_id": "T1046"},
    )

    assert "3389" in literals
    assert "14" not in literals
    assert "2000" not in literals
    assert "Review all relevant records." not in literals


def test_structured_wazuh_plan_rejects_invented_values():
    try:
        _compile_wazuh_plan(
            json.dumps({
                "clauses": [{
                    "field": "data.process.pid",
                    "operator": "term",
                    "value": "12345",
                }],
            }),
            ["data.process.pid"],
            ["nmap.exe", "T1046"],
        )
    except ValueError as exc:
        assert "ungrounded" in str(exc)
    else:
        raise AssertionError("invented query-plan value was accepted")


def test_structured_wazuh_plan_rejects_field_value_type_mismatch():
    try:
        _compile_wazuh_plan(
            json.dumps({
                "clauses": [{
                    "field": "source.ip",
                    "operator": "term",
                    "value": "8443",
                }],
            }),
            ["source.ip"],
            ["8443"],
            field_value_kinds={"source.ip": ["ip"]},
        )
    except ValueError as exc:
        assert "incompatible" in str(exc)
    else:
        raise AssertionError("numeric port was accepted as an IP address")


def test_structured_wazuh_plan_requires_each_representable_branch():
    branch_fields = {
        "Network Traffic": ["data.dest_port"],
        "Process Creation": ["data.process.name"],
    }
    try:
        _compile_wazuh_plan(
            json.dumps({
                "branches": {
                    "Process Creation": [{
                        "field": "data.process.name",
                        "operator": "match_phrase",
                        "value": "nmap.exe",
                    }],
                },
            }),
            ["data.dest_port", "data.process.name"],
            ["3389", "nmap.exe"],
            branch_fields,
        )
    except ValueError as exc:
        assert "Network Traffic" in str(exc)
    else:
        raise AssertionError("missing required evidence branch was accepted")


def test_structured_wazuh_plan_compiles_all_capability_branches():
    query = _compile_wazuh_plan(
        json.dumps({
            "branches": {
                "Network Traffic": [{
                    "field": "data.dest_port",
                    "operator": "term",
                    "value": "3389",
                }],
                "Process Creation": [{
                    "field": "data.process.name",
                    "operator": "match_phrase",
                    "value": "nmap.exe",
                }],
            },
        }),
        ["data.dest_port", "data.process.name"],
        ["3389", "nmap.exe"],
        {
            "Network Traffic": ["data.dest_port"],
            "Process Creation": ["data.process.name"],
        },
    )

    assert json.loads(query)["query"]["bool"]["minimum_should_match"] == 1


def test_governed_compiler_covers_each_branch_without_fixed_values():
    query = _compile_grounded_branch_query(
        {
            "Network Traffic": [
                "destination.port",
                "network.transport",
            ],
            "Process Creation": ["process.name"],
        },
        {
            "destination.port": ["integer"],
            "network.transport": ["protocol"],
            "process.name": ["artifact"],
        },
        ["8443", "TCP", "scanner.exe", "scanner"],
    )
    clause = json.loads(query)["query"]["bool"]

    assert {"term": {"destination.port": "8443"}} in clause["should"]
    assert {"term": {"network.transport": "TCP"}} in clause["should"]
    assert {
        "match_phrase": {"process.name": "scanner.exe"},
    } in clause["should"]
    assert clause["minimum_should_match"] == 1


def test_governed_compiler_prefers_configured_high_specificity_fields():
    query = _compile_grounded_branch_query(
        {
            "Network Traffic": [
                "source.port",
                "destination.port",
                "network.transport",
            ],
            "Process Creation": [
                "process.name",
                "process.command_line",
            ],
        },
        {
            "source.port": ["integer"],
            "destination.port": ["integer"],
            "network.transport": ["protocol"],
            "process.name": ["artifact"],
            "process.command_line": ["artifact"],
        },
        ["3389", "TCP", "scanner.exe", "scanner"],
        {
            "source.port": 45,
            "destination.port": 100,
            "network.transport": 20,
            "process.name": 100,
            "process.command_line": 95,
        },
    )
    clauses = json.loads(query)["query"]["bool"]["should"]

    assert {"term": {"destination.port": "3389"}} in clauses
    assert {"match_phrase": {"process.name": "scanner.exe"}} in clauses
    assert {"match_phrase": {"process.command_line": "scanner.exe"}} in clauses
    assert not any("source.port" in str(clause) for clause in clauses)
    assert not any("network.transport" in str(clause) for clause in clauses)


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
