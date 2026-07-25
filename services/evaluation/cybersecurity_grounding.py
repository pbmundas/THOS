"""Deterministic citation and abstention gates for cybersecurity answers."""
from __future__ import annotations

import re

_CITATION = re.compile(r"\[(CYBER:[A-Za-z0-9_.:-]+)\]")
_ABSTENTION = re.compile(
    r"\b(insufficient evidence|no authoritative source|cannot verify|"
    r"not present in the (?:retrieved )?knowledge|unable to substantiate)\b",
    re.IGNORECASE,
)


def citation_ids(answer: str) -> set[str]:
    return set(_CITATION.findall(answer or ""))


def evaluate_grounded_answer(answer: str, evidence: list[dict]) -> dict:
    available = {
        str(item.get("citation_id"))
        for item in evidence
        if str(item.get("citation_id", "")).startswith("CYBER:")
    }
    cited = citation_ids(answer)
    unknown = cited - available
    if not available:
        passed = bool(_ABSTENTION.search(answer or "")) and not cited
        reason = "correctly abstained" if passed else "answer must abstain when retrieval has no evidence"
    else:
        passed = bool(cited) and not unknown
        reason = (
            "citations grounded in retrieved evidence" if passed
            else "answer omitted citations" if not cited
            else "answer cited evidence that was not retrieved"
        )
    return {
        "passed": passed,
        "reason": reason,
        "available_citations": sorted(available),
        "cited": sorted(cited),
        "unknown_citations": sorted(unknown),
    }
