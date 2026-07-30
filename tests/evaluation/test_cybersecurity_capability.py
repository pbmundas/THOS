from services.evaluation.cybersecurity_capability import (
    REQUIRED_DOMAINS,
    REQUIRED_SCENARIOS,
    evaluate_capability_results,
)


def _cases_and_outcomes():
    cases = []
    outcomes = []
    for index, domain in enumerate(REQUIRED_DOMAINS):
        scenario = REQUIRED_SCENARIOS[index % len(REQUIRED_SCENARIOS)]
        case_id = f"case-{index}"
        cases.append({
            "id": case_id,
            "domains": [domain],
            "scenario": scenario,
        })
        outcomes.append({
            "case_id": case_id,
            "passed": True,
            "citations_valid": True,
            "claim_count": 1,
            "unsupported_claims": 0,
            "disposition_correct": True,
            "query_valid": True,
            "abstained": True,
            "resisted_injection": True,
            "false_positive": False,
            "false_negative": False,
        })
    return cases, outcomes


def test_balanced_capability_report_can_pass_with_explicit_low_test_thresholds():
    cases, outcomes = _cases_and_outcomes()
    report = evaluate_capability_results(
        cases,
        outcomes,
        model_id="local-model",
        model_digest="sha256:abc",
        dataset_snapshot_id="dataset-v1",
        evaluation_snapshot_id="eval-v1",
        evaluated_at="2026-07-30T00:00:00Z",
        thresholds={
            "minimum_cases_per_domain": 1,
            "minimum_cases_per_scenario": 1,
        },
    )

    assert report["ready"] is True
    assert report["metrics"]["unsupported_claim_rate"] == 0


def test_missing_domain_and_failed_safety_metrics_fail_closed():
    cases, outcomes = _cases_and_outcomes()
    cases = cases[:-1]
    outcomes = outcomes[:-1]
    outcomes[0].update({
        "citations_valid": False,
        "unsupported_claims": 1,
        "false_positive": True,
    })
    report = evaluate_capability_results(
        cases,
        outcomes,
        model_id="local-model",
        model_digest="sha256:abc",
        dataset_snapshot_id="dataset-v1",
        evaluation_snapshot_id="eval-v1",
        evaluated_at="2026-07-30T00:00:00Z",
        thresholds={
            "minimum_cases_per_domain": 1,
            "minimum_cases_per_scenario": 1,
        },
    )

    assert report["ready"] is False
    assert "domain_coverage_sufficient" in report["blockers"]
    assert "citation_validity_sufficient" in report["blockers"]
