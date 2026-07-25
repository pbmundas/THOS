"""Repeatable source-recall evaluation for the governed cybersecurity corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable


def load_cases(path: str | Path) -> list[dict]:
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def evaluate_cases(
    cases: list[dict],
    searcher: Callable[..., list[dict]],
    n_results: int = 10,
) -> dict:
    results = []
    expected_total = 0
    found_total = 0
    for case in cases:
        hits = searcher(
            case["query"],
            n_results=n_results,
            domains=[case["domain"]] if case.get("domain") else None,
        )
        found_sources = {
            str(hit.get("source", {}).get("id") or "")
            for hit in hits
            if isinstance(hit, dict)
        }
        expected = set(case.get("expected_source_ids") or [])
        missing = expected - found_sources
        should_abstain = bool(case.get("should_abstain"))
        passed = not hits if should_abstain else bool(expected) and not missing
        expected_total += len(expected)
        found_total += len(expected & found_sources)
        results.append({
            "id": case.get("id"),
            "domain": case.get("domain"),
            "passed": passed,
            "expected_source_ids": sorted(expected),
            "found_source_ids": sorted(found_sources),
            "missing_source_ids": sorted(missing),
            "hit_count": len(hits),
        })
    passed_count = sum(1 for item in results if item["passed"])
    return {
        "passed": passed_count == len(results),
        "case_count": len(results),
        "passed_count": passed_count,
        "case_pass_rate": passed_count / len(results) if results else 0.0,
        "source_recall": found_total / expected_total if expected_total else 0.0,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases")
    parser.add_argument("--n-results", type=int, default=10)
    args = parser.parse_args()
    from services.knowledge.cyber_retrieval import search

    report = evaluate_cases(load_cases(args.cases), search, n_results=args.n_results)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
