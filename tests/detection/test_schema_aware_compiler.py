from services.detection import sigma_query_catalog


def test_extracts_list_valued_sigma_fields():
    detection = {
        "selection": {
            "EventID": [4688, 1],
            "CommandLine|contains": ["powershell", "encodedcommand"],
        },
        "condition": "selection",
    }

    assert sigma_query_catalog._selection_fields(detection) == {"EventID", "CommandLine"}


def test_extracts_fields_from_list_of_selection_mappings():
    detection = {
        "selection": [
            {"Image|endswith": "\\powershell.exe"},
            {"CommandLine|contains": "-enc"},
        ],
        "condition": "selection",
    }

    assert sigma_query_catalog._selection_fields(detection) == {"Image", "CommandLine"}


def test_resolves_sigma_fields_against_discovered_inventory(monkeypatch):
    monkeypatch.setattr(
        sigma_query_catalog.siem_kb,
        "get_field_mapping",
        lambda _siem: {
            "event_id": "data.win.system.eventID",
            "command_line": "data.win.eventdata.commandLine",
        },
    )
    raw = {
        "detection": {
            "selection": {
                "EventID": 4688,
                "CommandLine|contains": "powershell",
            },
            "condition": "selection",
        }
    }
    snapshot = {
        "hit": True,
        "fields": [
            {"name": "data.win.system.eventID", "type": "int"},
            {"name": "data.win.eventdata.commandLine", "type": "string"},
        ],
    }

    mapping, missing = sigma_query_catalog._resolve_field_map(raw, "wazuh", snapshot)

    assert mapping == {
        "CommandLine": "data.win.eventdata.commandLine",
        "EventID": "data.win.system.eventID",
    }
    assert missing == []


def test_unmapped_field_fails_closed(monkeypatch):
    monkeypatch.setattr(
        sigma_query_catalog.siem_kb,
        "get_field_mapping",
        lambda _siem: {},
    )
    raw = {
        "detection": {
            "selection": {"VendorOnlyField": "value"},
            "condition": "selection",
        }
    }
    snapshot = {"hit": True, "fields": [{"name": "known.field", "type": "string"}]}

    mapping, missing = sigma_query_catalog._resolve_field_map(raw, "splunk", snapshot)

    assert mapping == {}
    assert missing == ["VendorOnlyField"]


def test_dynamic_schema_compilation_can_enable_static_catalog_rule(monkeypatch):
    catalog_entry = {
        "rule_id": "rule-1",
        "title": "Network scanner",
        "backend": "wazuh",
        "status": "unsupported",
        "query": None,
        "tags": ["attack.t1046"],
    }
    monkeypatch.setattr(
        sigma_query_catalog,
        "load_catalog",
        lambda: {"entries": [catalog_entry]},
    )
    monkeypatch.setattr(
        sigma_query_catalog,
        "_schema_context",
        lambda _backend: ({"hit": True}, "schema-1", False),
    )
    monkeypatch.setattr(
        sigma_query_catalog.cache,
        "cache_get",
        lambda *_args: {
            "rule_id": "rule-1",
            "status": "ready",
            "query": '{"query":{"match_all":{}}}',
            "schema_version": "schema-1",
        },
    )

    entries, coverage = sigma_query_catalog.applicable_rules(
        "wazuh",
        technique_id="T1046",
    )

    assert [item["rule_id"] for item in entries] == ["rule-1"]
    assert coverage == {
        "relevant": 1,
        "ready": 1,
        "unsupported": 0,
        "truncated": 0,
    }


def test_configured_semantic_mapping_wins_over_unrelated_leaf_match(monkeypatch):
    monkeypatch.setattr(
        sigma_query_catalog.siem_kb,
        "get_field_mapping",
        lambda _siem: {"process_name": "data.process.name / data.win.eventdata.image"},
    )
    raw = {
        "detection": {
            "selection": {"Image|endswith": "/nmap"},
            "condition": "selection",
        }
    }
    snapshot = {
        "hit": True,
        "fields": [
            {"name": "data.docker.Actor.Attributes.image", "type": "keyword"},
            {"name": "data.process.name", "type": "keyword"},
        ],
    }

    mapping, missing = sigma_query_catalog._resolve_field_map(raw, "wazuh", snapshot)

    assert mapping == {"Image": "data.process.name"}
    assert missing == []
