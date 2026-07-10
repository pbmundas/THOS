"""
Unit tests for services.siem.logrhythm._normalize_record.

This is a pure function (dict in -> dict out, no I/O), so it's tested
directly against representative raw LogRhythm payload shapes rather than
mocking the HTTP layer.
"""
from services.siem.logrhythm import _normalize_record


def test_normalize_record_primary_field_names():
    raw = {
        "normalDate": "2026-07-10T12:00:00.000Z",
        "impactedName": "WIN-DC01",
        "login": "jdoe",
        "commonEventName": "Process Create",
        "message": "powershell.exe -enc ...",
        "originIP": "10.0.0.5",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "2026-07-10T12:00:00.000Z"
    assert rec["host"] == "WIN-DC01"
    assert rec["user"] == "jdoe"
    assert rec["event"] == "Process Create"
    assert rec["detail"] == "powershell.exe -enc ..."
    assert rec["src_ip"] == "10.0.0.5"


def test_normalize_record_falls_back_to_alias_field_names():
    # Different LogRhythm KB config surfaces a different set of field names
    # for the same concepts -- _pick should walk the alias list.
    raw = {
        "normalDateMin": "2026-07-10T12:05:00.000Z",
        "hostName": "WIN-DC02",
        "loginName": "asmith",
        "classificationName": "Logon Failure",
        "logMessage": "failed logon attempt",
        "sourceIP": "10.0.0.9",
    }
    rec = _normalize_record(raw)

    assert rec["timestamp"] == "2026-07-10T12:05:00.000Z"
    assert rec["host"] == "WIN-DC02"
    assert rec["user"] == "asmith"
    assert rec["event"] == "Logon Failure"
    assert rec["detail"] == "failed logon attempt"
    assert rec["src_ip"] == "10.0.0.9"


def test_normalize_record_missing_fields_use_defaults():
    rec = _normalize_record({})

    assert rec["timestamp"] == ""
    assert rec["host"] == ""
    assert rec["user"] == ""
    # "event" is the one field with an explicit non-empty default.
    assert rec["event"] == "event"
    assert rec["detail"] == ""
    assert rec["src_ip"] == ""


def test_normalize_record_ignores_empty_string_values_when_checking_aliases():
    # An empty string for the first alias should not "win" over a populated
    # later alias -- _pick treats "" the same as missing.
    raw = {"impactedName": "", "hostName": "WIN-DC03"}
    rec = _normalize_record(raw)
    assert rec["host"] == "WIN-DC03"


def test_normalize_record_preserves_raw_payload():
    raw = {"impactedName": "WIN-DC01", "someVendorSpecificField": "value"}
    rec = _normalize_record(raw)
    assert rec["_raw"] == raw
    assert rec["_raw"] is raw
