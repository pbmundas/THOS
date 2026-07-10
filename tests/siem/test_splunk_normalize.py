"""
Unit tests for services.siem.splunk._normalize_record and _normalize_spl.

Both are pure functions (no I/O), tested directly against representative
Splunk result/SPL shapes rather than mocking the HTTP layer.
"""
from services.siem.splunk import _normalize_record, _normalize_spl


# --------------------------------------------------------------------
# _normalize_record
# --------------------------------------------------------------------

def test_normalize_record_primary_field_names():
    raw = {
        "_time": "2026-07-10T12:00:00.000Z",
        "host": "web01",
        "user": "jdoe",
        "sourcetype": "wineventlog",
        "_raw": "raw splunk event text",
        "src_ip": "10.0.0.5",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "2026-07-10T12:00:00.000Z"
    assert rec["host"] == "web01"
    assert rec["user"] == "jdoe"
    assert rec["event"] == "wineventlog"
    assert rec["detail"] == "raw splunk event text"
    assert rec["src_ip"] == "10.0.0.5"


def test_normalize_record_falls_back_to_cim_alias_field_names():
    raw = {
        "timestamp": "2026-07-10T12:05:00.000Z",
        "Computer": "WIN-DC02",
        "Account_Name": "asmith",
        "EventCode": "4625",
        "CommandLine": "cmd.exe /c whoami",
        "Source_Network_Address": "10.0.0.9",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "2026-07-10T12:05:00.000Z"
    assert rec["host"] == "WIN-DC02"
    assert rec["user"] == "asmith"
    assert rec["event"] == "4625"
    assert rec["detail"] == "cmd.exe /c whoami"
    assert rec["src_ip"] == "10.0.0.9"


def test_normalize_record_missing_fields_use_defaults():
    rec = _normalize_record({})

    assert rec["timestamp"] == ""
    assert rec["host"] == ""
    assert rec["user"] == ""
    assert rec["event"] == "event"
    assert rec["detail"] == ""
    assert rec["src_ip"] == ""


def test_normalize_record_preserves_raw_payload():
    raw = {"host": "web01", "someField": "value"}
    rec = _normalize_record(raw)
    assert rec["_raw"] is raw


# --------------------------------------------------------------------
# _normalize_spl
# --------------------------------------------------------------------

def test_normalize_spl_empty_query_defaults_to_wildcard_search():
    assert _normalize_spl("") == "search *"
    assert _normalize_spl(None) == "search *"
    assert _normalize_spl("   ") == "search *"


def test_normalize_spl_bare_filter_gets_search_prefix():
    assert _normalize_spl("index=main sourcetype=wineventlog") == \
        "search index=main sourcetype=wineventlog"


def test_normalize_spl_already_starting_with_search_is_untouched():
    q = "search index=main sourcetype=wineventlog"
    assert _normalize_spl(q) == q


def test_normalize_spl_is_case_insensitive_on_search_prefix():
    q = "SEARCH index=main"
    assert _normalize_spl(q) == q


def test_normalize_spl_generating_command_is_untouched():
    q = "| tstats count where index=main by host"
    assert _normalize_spl(q) == q


def test_normalize_spl_strips_surrounding_whitespace():
    assert _normalize_spl("  index=main  ") == "search index=main"
