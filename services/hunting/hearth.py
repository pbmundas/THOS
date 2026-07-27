"""
HEARTH hypothesis tool.

Phase 3: list_hypotheses()/get_hypothesis() now read from the 'hearth_kb'
Chroma collection, which is populated by services/knowledge/ingest_knowledge_base.py
from the full ingested HEARTH repository (data/knowledge_base/hearth/*.json —
see services/knowledge/seeds or scripts/fetch_hearth.py for how that JSON is
produced from https://github.com/THORCollective/HEARTH).

FALLBACK_HYPOTHESES below is used only if the KB hasn't been ingested yet
(e.g. first boot before `docker compose run --rm kb-ingest` / the kb-ingest
service has completed), so the platform still has *something* to show.
"""
import json
from pathlib import Path

from services.siem.clients import get_or_create_collection

FALLBACK_HYPOTHESES = [
    {
        "id": "H-001",
        "title": "Suspicious PowerShell Encoded Command Execution",
        "tactic": "Execution",
        "technique": "T1059.001",
        "text": "Adversaries may use base64-encoded PowerShell commands to "
                "evade detection while executing malicious payloads.",
    },
    {
        "id": "H-002",
        "title": "Anomalous Outbound DNS Volume (Possible Tunneling)",
        "tactic": "Command and Control",
        "technique": "T1071.004",
        "text": "A host generating an unusually high volume of DNS queries, "
                "especially to rare or newly-observed domains, may indicate "
                "DNS tunneling for C2 or exfiltration.",
    },
    {
        "id": "H-003",
        "title": "Lateral Movement via Admin Shares (PsExec-like)",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "text": "Adversaries may use valid accounts to connect to remote "
                "systems using SMB admin shares to move laterally.",
    },
]

_REQUIRED_GAP_PATH = Path(__file__).with_name("data") / "required_gap_hypotheses.json"


def _load_required_gap_hypotheses() -> list[dict]:
    try:
        payload = json.loads(_REQUIRED_GAP_PATH.read_text(encoding="utf-8"))
        return [item for item in payload if isinstance(item, dict) and item.get("id")]
    except (OSError, ValueError):
        return []


REQUIRED_GAP_HYPOTHESES = _load_required_gap_hypotheses()


def _meta_to_hypothesis(meta: dict) -> dict:
    return {
        "id": meta.get("id", ""),
        "title": meta.get("title", ""),
        "tactic": meta.get("tactic", ""),
        "technique": meta.get("technique", ""),
        "text": meta.get("text", ""),
        "severity": meta.get("severity", ""),
        "category": meta.get("category", ""),
    }


def _merge_required(items: list[dict]) -> list[dict]:
    merged = {str(item.get("id")): item for item in items if item.get("id")}
    for item in REQUIRED_GAP_HYPOTHESES:
        merged[str(item["id"])] = item
    return sorted(merged.values(), key=lambda item: str(item.get("id", "")))


def list_hypotheses(tactic: str | None = None) -> list[dict]:
    """Return available HEARTH hunting hypotheses, optionally filtered by ATT&CK tactic.

    Reads the fully ingested HEARTH repository from the 'hearth_kb' Chroma
    collection. Falls back to a 3-item seed set if the KB hasn't been
    ingested yet.
    """
    collection = get_or_create_collection("hearth_kb")
    if collection.count() == 0:
        results = FALLBACK_HYPOTHESES
        if tactic:
            results = [h for h in results if h["tactic"].lower() == tactic.lower()]
        return _merge_required(results)

    where = {"tactic": tactic} if tactic else None
    res = collection.get(where=where, include=["metadatas"])
    hypotheses = [_meta_to_hypothesis(m) for m in res.get("metadatas", [])]
    if tactic:
        required = [
            item for item in REQUIRED_GAP_HYPOTHESES
            if str(item.get("tactic", "")).casefold() == tactic.casefold()
        ]
        return _merge_required([*hypotheses, *required])
    return _merge_required(hypotheses)


def get_hypothesis(hypothesis_id: str) -> dict | None:
    collection = get_or_create_collection("hearth_kb")
    if collection.count() > 0:
        res = collection.get(ids=[hypothesis_id], include=["metadatas"])
        metas = res.get("metadatas", [])
        if metas:
            return _meta_to_hypothesis(metas[0])
    for h in FALLBACK_HYPOTHESES:
        if h["id"] == hypothesis_id:
            return h
    for h in REQUIRED_GAP_HYPOTHESES:
        if h["id"] == hypothesis_id:
            return h
    return None


def semantic_search_hypotheses(query: str, n_results: int = 3) -> list[dict]:
    """RAG lookup against the hearth_kb Chroma collection (populated separately)."""
    collection = get_or_create_collection("hearth_kb")
    if collection.count() == 0:
        return []
    res = collection.query(query_texts=[query], n_results=n_results)
    docs = res.get("documents", [[]])[0]
    metas = res.get("metadatas", [[]])[0]
    return [{"text": d, "meta": m} for d, m in zip(docs, metas)]
