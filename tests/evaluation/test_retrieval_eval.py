from services.evaluation.retrieval_eval import evaluate_cases


def test_retrieval_eval_measures_source_recall_and_abstention():
    cases = [
        {
            "id": "positive",
            "domain": "incident_response",
            "query": "incident response",
            "expected_source_ids": ["nist"],
        },
        {
            "id": "negative",
            "domain": "threat_hunting",
            "query": "private unpublished indicators",
            "expected_source_ids": [],
            "should_abstain": True,
        },
    ]

    def searcher(query, **_kwargs):
        if query == "incident response":
            return [{"source": {"id": "nist"}}]
        return []

    report = evaluate_cases(cases, searcher)

    assert report["passed"] is True
    assert report["case_pass_rate"] == 1.0
    assert report["source_recall"] == 1.0
