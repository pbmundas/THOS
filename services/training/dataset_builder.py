"""Build fine-tuning data only from human-verified, evidence-cited examples."""
from __future__ import annotations

import json
from pathlib import Path

from services.evaluation.cybersecurity_grounding import evaluate_grounded_answer
from services.knowledge.cyber_corpus import load_manifest


class TrainingDataError(ValueError):
    pass


def approved_source_ids(manifest_path: str | Path) -> set[str]:
    return {
        source.id for source in load_manifest(manifest_path)
        if source.enabled and source.license != "PROPRIETARY-LICENSE-REQUIRED"
    }


def validate_example(example: dict, approved_sources: set[str]) -> dict:
    if example.get("human_verified") is not True:
        raise TrainingDataError("example is not human_verified")
    if not str(example.get("question", "")).strip() or not str(example.get("answer", "")).strip():
        raise TrainingDataError("question and answer are required")
    evidence = example.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise TrainingDataError("retrieved evidence is required")
    used_sources = {
        str(item.get("source", {}).get("id") or "")
        for item in evidence if isinstance(item, dict)
    }
    if not used_sources or not used_sources <= approved_sources:
        raise TrainingDataError("example references an unapproved or disabled source")
    grounding = evaluate_grounded_answer(str(example["answer"]), evidence)
    if not grounding["passed"]:
        raise TrainingDataError(grounding["reason"])
    return grounding


def build_sft_records(examples: list[dict], manifest_path: str | Path) -> tuple[list[dict], list[dict]]:
    approved = approved_source_ids(manifest_path)
    records, rejected = [], []
    for example in examples:
        try:
            validate_example(example, approved)
        except TrainingDataError as exc:
            rejected.append({"id": example.get("id"), "reason": str(exc)})
            continue
        evidence_text = "\n\n".join(
            f"[{item['citation_id']}] {item.get('text', '')}" for item in example["evidence"]
        )
        records.append({
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity assistant. Use only supplied evidence, "
                        "cite [CYBER:*] IDs, and abstain when evidence is insufficient."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Evidence:\n{evidence_text}\n\nQuestion:\n{example['question']}",
                },
                {"role": "assistant", "content": example["answer"]},
            ],
            "metadata": {
                "id": example.get("id"),
                "domain": example.get("domain"),
                "verified_by": example.get("verified_by"),
                "source_ids": sorted({
                    item["source"]["id"] for item in example["evidence"]
                }),
            },
        })
    return records, rejected


def load_jsonl(path: str | Path) -> list[dict]:
    return [
        json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: str | Path, records: list[dict]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )
