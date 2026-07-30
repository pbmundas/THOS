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
from services.siem.clients import get_or_create_collection
from services.hunting.hypothesis_catalog import (
    canonical_hypotheses,
    hypothesis_document,
    is_canonical_hypothesis_id,
    metadata_to_hypothesis,
    normalize_hypothesis,
)

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

def _meta_to_hypothesis(meta: dict) -> dict:
    return metadata_to_hypothesis(meta)


def list_hypotheses(tactic: str | None = None) -> list[dict]:
    """Return available HEARTH hunting hypotheses, optionally filtered by ATT&CK tactic.

    Reads the fully ingested HEARTH repository from the 'hearth_kb' Chroma
    collection. Falls back to a 3-item seed set if the KB hasn't been
    ingested yet.
    """
    collection = get_or_create_collection("hearth_kb")
    if collection.count() == 0:
        results = [normalize_hypothesis(item) for item in FALLBACK_HYPOTHESES]
        if tactic:
            results = [h for h in results if h["tactic"].lower() == tactic.lower()]
        return results

    res = collection.get(include=["metadatas"])
    hypotheses = canonical_hypotheses(
        _meta_to_hypothesis(meta) for meta in res.get("metadatas", [])
    )
    if tactic:
        hypotheses = [
            item for item in hypotheses
            if str(item.get("tactic", "")).casefold() == tactic.casefold()
        ]
    return hypotheses


def get_hypothesis(hypothesis_id: str) -> dict | None:
    if not is_canonical_hypothesis_id(hypothesis_id):
        return None
    collection = get_or_create_collection("hearth_kb")
    if collection.count() > 0:
        res = collection.get(ids=[hypothesis_id], include=["metadatas"])
        metas = res.get("metadatas", [])
        if metas:
            return _meta_to_hypothesis(metas[0])
    for h in FALLBACK_HYPOTHESES:
        if h["id"] == hypothesis_id:
            return normalize_hypothesis(h)
    return None


def semantic_search_hypotheses(query: str, n_results: int = 3) -> list[dict]:
    """RAG lookup against the hearth_kb Chroma collection (populated separately)."""
    collection = get_or_create_collection("hearth_kb")
    if collection.count() == 0:
        return []
    requested = max(1, int(n_results))
    candidate_count = min(collection.count(), max(requested * 6, requested))
    res = collection.query(query_texts=[query], n_results=candidate_count)
    docs = res.get("documents", [[]])[0]
    metas = res.get("metadatas", [[]])[0]
    results = []
    for document, meta in zip(docs, metas):
        item = _meta_to_hypothesis(meta)
        if not is_canonical_hypothesis_id(item.get("id")):
            continue
        results.append({
            "text": document or hypothesis_document(item),
            "meta": item,
        })
        if len(results) >= requested:
            break
    return results
