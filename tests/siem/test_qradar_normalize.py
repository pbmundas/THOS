"""
Unit tests for services.siem.qradar._normalize_record and _add_time_window.

Both are pure functions (no I/O -- _add_time_window only reads the wall
clock to compute a lookback window), tested directly against
representative AQL/result shapes rather than mocking the HTTP layer.
"""
import re

from services.siem.qradar import _normalize_record, _add_time_window

_START_STOP_RE = re.compile(
    r"START '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' "
    r"STOP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'$"
)


# --------------------------------------------------------------------
# _normalize_record
# --------------------------------------------------------------------

def test_normalize_record_primary_field_names():
    raw = {
        "starttime": "1720612800000",
        "sourceip": "10.0.0.5",
        "username": "jdoe",
        "qidname": "Process Created",
        "payload": "powershell.exe -enc ...",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "1720612800000"
    assert rec["host"] == "10.0.0.5"  # QRadar has no dedicated host alias here
    assert rec["user"] == "jdoe"
    assert rec["event"] == "Process Created"
    assert rec["detail"] == "powershell.exe -enc ..."
    assert rec["src_ip"] == "10.0.0.5"


def test_normalize_record_falls_back_to_alias_field_names():
    raw = {
        "devicetime": "1720612900000",
        "logsourcename": "WinCollect01",
        "identityusername": "asmith",
        "categoryname": "Authentication Failure",
        "message": "failed logon",
        "Source IP": "10.0.0.9",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "1720612900000"
    assert rec["host"] == "WinCollect01"
    assert rec["user"] == "asmith"
    assert rec["event"] == "Authentication Failure"
    assert rec["detail"] == "failed logon"
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
    raw = {"sourceip": "10.0.0.5"}
    rec = _normalize_record(raw)
    assert rec["_raw"] is raw


# --------------------------------------------------------------------
# _add_time_window
# --------------------------------------------------------------------

def test_add_time_window_empty_aql_defaults_to_select_all():
    aql = _add_time_window("", lookback_minutes=60, limit=25)
    assert aql.startswith("SELECT * FROM events LIMIT 25")
    assert _START_STOP_RE.search(aql)


def test_add_time_window_bare_where_fragment_gets_wrapped():
    aql = _add_time_window("sourceip='10.0.0.5'", lookback_minutes=60, limit=25)
    assert aql.startswith("SELECT * FROM events WHERE sourceip='10.0.0.5' LIMIT 25")
    assert _START_STOP_RE.search(aql)


def test_add_time_window_adds_limit_when_absent():
    aql = _add_time_window("SELECT * FROM events", lookback_minutes=60, limit=10)
    assert "LIMIT 10" in aql


def test_add_time_window_does_not_duplicate_existing_limit():
    aql = _add_time_window("SELECT * FROM events LIMIT 5", lookback_minutes=60, limit=25)
    assert aql.count("LIMIT") == 1
    assert "LIMIT 5" in aql


def test_add_time_window_skips_start_stop_when_start_clause_present():
    original = "SELECT * FROM events START '2026-07-01 00:00:00' STOP '2026-07-02 00:00:00'"
    aql = _add_time_window(original, lookback_minutes=60, limit=25)
    # No new START/STOP appended -- the existing clause is left as-is.
    assert aql.count("START") == 1
    assert aql.count("STOP") == 1


def test_add_time_window_skips_start_stop_when_last_clause_present_case_insensitive():
    original = "SELECT * FROM events last 2 hours"
    aql = _add_time_window(original, lookback_minutes=60, limit=25)
    assert "START" not in aql.upper() or aql.upper().count("START") == 0


def test_add_time_window_strips_trailing_semicolon():
    aql = _add_time_window("SELECT * FROM events;", lookback_minutes=60, limit=25)
    assert ";" not in aql
