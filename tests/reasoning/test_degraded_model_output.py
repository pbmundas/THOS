from services.hunting.query_generator import _fallback_query
from services.reasoning.reasoning import _deterministic_fallback


def test_empty_model_fallback_is_not_an_empty_report():
    result = _deterministic_fallback(
        {"processed_logs": [{"event": "4104"}], "sigma_matched_refs": [0], "sigma_matched_count": 1},
        {"4104": 1},
    )
    assert "Degraded analysis" in result["summary"]
    assert result["findings"][0]["ref"] == "0"
    assert result["recommendations"]


def test_folder_query_fallback_is_nonempty():
    assert _fallback_query("Suspicious PowerShell script activity", "folder")
    assert _fallback_query("Suspicious PowerShell script activity", "splunk") == "*"
