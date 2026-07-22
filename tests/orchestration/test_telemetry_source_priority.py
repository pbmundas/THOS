from services.api.control_plane import telemetry_sources


def test_folder_is_primary_when_no_live_siem_is_connected():
    result = telemetry_sources({"general": {"default_siem": "folder"}, "siem": {}})
    assert [item["id"] for item in result["items"]] == ["folder"]
    assert result["default"] == "folder"


def test_connected_live_siem_becomes_primary_and_folder_is_fallback():
    result = telemetry_sources({
        "general": {"default_siem": "folder"},
        "siem": {"wazuh": {"connection_status": "connected", "connection_tested_at": "now"}},
    })
    assert [item["id"] for item in result["items"]] == ["wazuh", "folder"]
    assert result["default"] == "wazuh"


def test_explicit_connected_live_default_is_preserved():
    result = telemetry_sources({
        "general": {"default_siem": "splunk"},
        "siem": {
            "wazuh": {"connection_status": "connected"},
            "splunk": {"connection_status": "connected"},
        },
    })
    assert [item["id"] for item in result["items"]] == ["wazuh", "splunk", "folder"]
    assert result["default"] == "splunk"
