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
    return {
        "id": meta.get("id", ""),
        "title": meta.get("title", ""),
        "tactic": meta.get("tactic", ""),
        "technique": meta.get("technique", ""),
        "text": meta.get("text", ""),
    }


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
        return results

    where = {"tactic": tactic} if tactic else None
    res = collection.get(where=where, include=["metadatas"])
    hypotheses = [_meta_to_hypothesis(m) for m in res.get("metadatas", [])]
    hypotheses.sort(key=lambda h: h["id"])
    return hypotheses


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
