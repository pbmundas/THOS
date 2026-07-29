import asyncio

from services.hunting import evidence_selector
from services.reasoning.reasoning import _slim_log


def test_nmap_evidence_is_selected_by_agent_and_literal_validated(monkeypatch):
    record = {
        "event": "Web server 400 error code.",
        "detail": "x" * 2_000,
        "evidence_summary": (
            "URL: /nmaplowercheck; full log: Mozilla/5.0 "
            "(compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        ),
    }

    async def fake_decide_json(**kwargs):
        return kwargs["validator"]({
            "assessment": "The record contains a literal scanner artifact.",
            "evidence": [{
                "record_index": 0,
                "kind": "artifact",
                "claim": "Nmap scripting-engine text is present.",
                "matched_literals": ["Nmap Scripting Engine"],
            }],
        })

    monkeypatch.setattr(evidence_selector, "decide_json", fake_decide_json)
    result = asyncio.run(evidence_selector.select_hunt_evidence(
        logs=[record],
        hypothesis_text="Investigate network service discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="discovery",
        objective="Find service discovery evidence",
        indicators={},
        detection_rule_refs=[],
    ))
    slim = _slim_log(record, ref=0)

    assert "Nmap Scripting Engine" in slim["evidence_summary"]
    assert slim["detail"].endswith("(truncated)")
    assert result["evidence"][0]["record_index"] == 0
    assert result["evidence"][0]["matched_literals"] == [
        "Nmap Scripting Engine"
    ]
