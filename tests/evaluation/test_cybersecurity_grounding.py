from services.evaluation.cybersecurity_grounding import evaluate_grounded_answer


EVIDENCE = [{
    "citation_id": "CYBER:mitre_attack_enterprise:T1003:0",
    "text": "Credential dumping description.",
}]


def test_grounded_answer_requires_a_retrieved_citation():
    passed = evaluate_grounded_answer(
        "ATT&CK describes credential dumping [CYBER:mitre_attack_enterprise:T1003:0].",
        EVIDENCE,
    )
    missing = evaluate_grounded_answer("ATT&CK describes credential dumping.", EVIDENCE)
    invented = evaluate_grounded_answer(
        "Claim [CYBER:invented:record:0].", EVIDENCE,
    )

    assert passed["passed"] is True
    assert missing["passed"] is False
    assert invented["unknown_citations"] == ["CYBER:invented:record:0"]


def test_no_evidence_requires_explicit_abstention():
    assert evaluate_grounded_answer(
        "I cannot verify this because no authoritative source was retrieved.", [],
    )["passed"] is True
    assert evaluate_grounded_answer("This is definitely malicious.", [])["passed"] is False
