#!/usr/bin/env python3
"""
THOS knowledge-base ingestion.

Reads the seed JSON files under /data/knowledge_base/{hearth,mitre,siem_kb}
and loads them into ChromaDB collections so the MCP tools' semantic-search
functions (hearth.semantic_search_hypotheses, and future siem_kb / mitre
semantic lookups) have something to query.

Run this:
  - automatically via the one-shot `kb-ingest` service in docker-compose
  - manually any time you add new seed files:
      docker compose run --rm kb-ingest

Phase 3+ extension point: point this at real external corpora instead of
the seed JSON — the full HEARTH GitHub repo, the MITRE ATT&CK STIX bundle,
your organization's actual SIEM field dictionary, SigmaHQ rules, etc.
Chunk large documents (~500 tokens) before embedding for better recall.
"""
import os
import json
import glob
import time

import chromadb
from chromadb.config import Settings

CHROMA_HOST = os.environ.get("CHROMA_HOST", "chromadb")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
KB_ROOT = os.environ.get("KB_ROOT", "/data/knowledge_base")
CYBER_CORPUS_MANIFEST = os.environ.get(
    "CYBER_CORPUS_MANIFEST", "/data/knowledge_sources/cybersecurity_sources.json",
)


def get_client(retries: int = 20, delay: float = 3.0):
    last_err = None
    for _ in range(retries):
        try:
            client = chromadb.HttpClient(
                host=CHROMA_HOST, port=CHROMA_PORT,
                settings=Settings(anonymized_telemetry=False),
            )
            client.heartbeat()
            return client
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}: {last_err}")


def ingest_hearth(client):
    """Ingest HEARTH hypotheses into the 'hearth_kb' collection.

    Tries a live fetch from https://github.com/THORCollective/HEARTH first
    (so every `docker compose up` / kb-ingest run picks up whatever new
    hypotheses THOR Collective has published since last time). Falls back
    to whatever local JSON is under KB_ROOT/hearth/*.json if the fetch
    fails (e.g. an air-gapped/fully on-prem deployment with no route to
    github.com) — this platform is meant to still work fully offline.
    """
    collection = client.get_or_create_collection("hearth_kb")
    ids, docs, metas = [], [], []
    source = "unknown"

    try:
        from services.knowledge.hearth_fetch import fetch_and_parse_hearth
        items = fetch_and_parse_hearth()
        source = "live GitHub fetch"
        # Cache what we fetched to disk too, so the local-file fallback
        # path below stays fresh for the next offline run.
        try:
            cache_dir = os.path.join(KB_ROOT, "hearth")
            os.makedirs(cache_dir, exist_ok=True)
            with open(os.path.join(cache_dir, "hearth_full.json"), "w", encoding="utf-8") as f:
                json.dump(items, f, indent=2)
        except OSError as e:
            print(f"[hearth_kb] warning: could not cache fetched hypotheses to disk: {e}")
    except Exception as e:  # noqa: BLE001 - network/parents errors, fall back to local files
        print(f"[hearth_kb] live fetch failed ({e}); falling back to local JSON under {KB_ROOT}/hearth/")
        items = []
        for path in glob.glob(os.path.join(KB_ROOT, "hearth", "*.json")):
            with open(path) as f:
                items.extend(json.load(f))
        source = f"local JSON ({KB_ROOT}/hearth/*.json)"

    # THOS-required gap hypotheses are versioned with the application and
    # overlay the upstream HEARTH feed. They cover techniques for which the
    # live SIEM schema has runnable Sigma detections but HEARTH has no exact
    # hypothesis. Upstream refreshes must never erase this local coverage.
    from services.hunting.hearth import REQUIRED_GAP_HYPOTHESES
    items_by_id = {str(item["id"]): item for item in items if item.get("id")}
    items_by_id.update({
        str(item["id"]): item for item in REQUIRED_GAP_HYPOTHESES
        if item.get("id")
    })
    items = list(items_by_id.values())

    for h in items:
        ids.append(h["id"])
        docs.append(f'{h["title"]}. {h["text"]}')
        metas.append({
            "id": h["id"], "title": h["title"], "tactic": h.get("tactic", ""),
            "technique": h.get("technique", ""), "text": h["text"],
            "severity": h.get("severity", ""), "category": h.get("category", ""),
        })
    if ids:
        existing_ids = set(collection.get(include=[]).get("ids", []))
        stale_ids = sorted(existing_ids - set(ids))
        if stale_ids:
            collection.delete(ids=stale_ids)
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
    print(f"[hearth_kb] ingested {len(ids)} hypotheses from {source}")


def ingest_mitre(client):
    collection = client.get_or_create_collection("mitre_kb")
    files = glob.glob(os.path.join(KB_ROOT, "mitre", "*.json"))
    ids, docs, metas = [], [], []
    for path in files:
        with open(path) as f:
            items = json.load(f)
        for t in items:
            ids.append(t["id"])
            docs.append(f'{t["id"]} {t["name"]}: {t["description"]}')
            metas.append({
                "id": t["id"], "name": t["name"], "tactic": t.get("tactic", ""),
                "description": t.get("description", ""),
                "data_sources": ",".join(t.get("data_sources", [])),
            })
    if ids:
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
    print(f"[mitre_kb] ingested {len(ids)} techniques from {len(files)} file(s)")


def ingest_siem_kb(client):
    collection = client.get_or_create_collection("siem_kb")
    files = glob.glob(os.path.join(KB_ROOT, "siem_kb", "*.json"))
    ids, docs, metas = [], [], []
    for path in files:
        with open(path) as f:
            items = json.load(f)
        for entry in items:
            key = f'{entry["siem_type"]}:{entry["normalized_field"]}'
            ids.append(key)
            docs.append(f'{entry["normalized_field"]} maps to {entry["vendor_field"]} in {entry["siem_type"]}. {entry.get("notes", "")}')
            metas.append(entry)
    if ids:
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
    print(f"[siem_kb] ingested {len(ids)} field mappings from {len(files)} file(s)")


def ingest_cyber_corpus(client):
    if os.environ.get("CYBER_CORPUS_ENABLED", "1") != "1":
        print("[cyber_domain_kb] disabled")
        return
    try:
        from services.knowledge.cyber_corpus import COLLECTION_NAME, ingest_manifest
        configured_ids = {
            item.strip()
            for item in os.environ.get("CYBER_CORPUS_SOURCE_IDS", "").split(",")
            if item.strip()
        }
        result = ingest_manifest(
            client.get_or_create_collection(COLLECTION_NAME),
            CYBER_CORPUS_MANIFEST,
            source_ids=configured_ids or None,
        )
        print(f"[cyber_domain_kb] {json.dumps(result, default=str)}")
        if result["status"] == "failed":
            raise RuntimeError("one or more required cybersecurity sources failed")
    except Exception as exc:
        if os.environ.get("CYBER_CORPUS_REQUIRED", "0") == "1":
            raise
        print(f"[cyber_domain_kb] degraded: {exc}")


def main():
    client = get_client()
    ingest_hearth(client)
    ingest_mitre(client)
    ingest_siem_kb(client)
    ingest_cyber_corpus(client)
    print("Knowledge base ingestion complete.")


if __name__ == "__main__":
    main()
