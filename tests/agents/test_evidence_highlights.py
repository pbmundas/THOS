from services.mcp.soc_tools import _artifact_highlights
from services.reasoning.reasoning import _slim_log


def test_nmap_nse_survives_raw_detail_prompt_truncation():
    record = {
        "event": "Web server 400 error code.",
        "detail": "x" * 2_000,
        "evidence_summary": (
            "URL: /nmaplowercheck; full log: Mozilla/5.0 "
            "(compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        ),
    }

    slim = _slim_log(record, ref=0)
    highlights = _artifact_highlights([record], "T1046", "Network Service Discovery")

    assert "Nmap Scripting Engine" in slim["evidence_summary"]
    assert slim["detail"].endswith("(truncated)")
    assert highlights[0]["record_index"] == 0
    assert "nmap scripting engine" in highlights[0]["matched_artifacts"]
