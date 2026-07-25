"""Provenance-preserving retrieval from the governed cybersecurity corpus."""
from __future__ import annotations

import os
import re

from services.knowledge.cyber_corpus import COLLECTION_NAME
from services.siem.clients import get_or_create_collection

_STOP = {"the", "and", "for", "from", "with", "that", "this", "what", "how", "into", "are"}
_NON_PUBLIC_TERMS = {"private", "unpublished", "confidential", "non-public", "internal-only"}
_FRESH_OBSERVATION_TERMS = {"today", "currently", "latest", "observed", "reported", "indicators", "incident"}


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9_.-]{3,}", value.lower())
        if token not in _STOP
    }


def search(query: str, n_results: int = 6, domains: list[str] | None = None) -> list[dict]:
    if not (query or "").strip():
        return []
    query_terms = _tokens(query)
    # This corpus contains public, versioned references. A request that
    # explicitly requires private/unpublished current observations cannot be
    # grounded here, even when generic words happen to overlap a rule.
    if query_terms.intersection(_NON_PUBLIC_TERMS) and query_terms.intersection(_FRESH_OBSERVATION_TERMS):
        return []
    collection = get_or_create_collection(COLLECTION_NAME)
    if collection.count() == 0:
        return []
    requested = max(1, min(int(n_results), 10))
    # Retrieve a wider candidate pool before applying curriculum-domain,
    # lexical, provenance, and diversity gates. A global top-40 query was
    # easily monopolized by one long source (for example a NIST PDF), hiding
    # complementary ATT&CK/Sigma evidence even when both were directly relevant.
    candidate_count = min(max(requested * 16, 64), 200, collection.count())
    result = collection.query(query_texts=[query], n_results=candidate_count)
    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    distances = (result.get("distances") or [[]])[0]
    domain_set = {item.strip().lower() for item in (domains or []) if item.strip()}
    query_tokens = query_terms
    max_distance = float(os.environ.get("CYBER_KB_MAX_DISTANCE", "1.35"))
    candidates = []
    for text, metadata, distance in zip(documents, metadatas, distances):
        metadata = metadata or {}
        source_domains = {item for item in str(metadata.get("domains", "")).split(",") if item}
        if domain_set and not source_domains.intersection(domain_set):
            continue
        overlap = len(query_tokens & _tokens(f"{metadata.get('record_title', '')} {text}"))
        # Embedding similarity alone is not sufficient for an evidence-backed
        # answer: an unanswerable "private indicators observed today" query once
        # returned an unrelated Sigma rule at distance 1.25 with zero shared
        # terms. Require at least one lexical anchor and keep the distance gate.
        if overlap == 0 or (distance is not None and float(distance) > max_distance):
            continue
        citation_id = str(metadata.get("citation_id") or "")
        if not citation_id.startswith("CYBER:"):
            continue
        candidates.append({
            "citation_id": citation_id,
            "text": str(text)[:2_400],
            "source": {
                "id": metadata.get("source_id"),
                "title": metadata.get("source_title"),
                "record": metadata.get("record_title"),
                "publisher": metadata.get("publisher"),
                "license": metadata.get("license"),
                "license_url": metadata.get("license_url"),
                "retrieved_at": metadata.get("retrieved_at"),
                "trust_tier": metadata.get("trust_tier"),
            },
            "domains": sorted(source_domains),
            "distance": distance,
            "lexical_overlap": overlap,
        })
    # First include the strongest result from each relevant source, then fill
    # the remaining slots in similarity order. This preserves source diversity
    # for cross-framework questions without fabricating a source requirement.
    hits, seen_sources, seen_citations = [], set(), set()
    for item in candidates:
        source_id = str(item["source"].get("id") or "")
        if source_id in seen_sources:
            continue
        hits.append(item)
        seen_sources.add(source_id)
        seen_citations.add(item["citation_id"])
        if len(hits) >= requested:
            return hits
    for item in candidates:
        if item["citation_id"] in seen_citations:
            continue
        hits.append(item)
        if len(hits) >= requested:
            break
    return hits
