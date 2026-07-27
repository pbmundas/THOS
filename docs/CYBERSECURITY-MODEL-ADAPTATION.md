# THOS cybersecurity model adaptation

THOS separates knowledge from behavior:

- Current, factual cybersecurity knowledge belongs in the governed RAG corpus.
- Model-weight adaptation is reserved for stable behaviors: citation discipline,
  abstention, THOS JSON schemas, investigation structure, and organization
  terminology.
- Raw advisories, CVEs, changing ATT&CK content, and vendor details should not
  be memorized through fine-tuning because they become stale.

## Curriculum

The source manifest is
`data/knowledge_sources/cybersecurity_sources.json`. It initially covers:

- MITRE ATT&CK Enterprise for red-team, threat-hunting, detection, and
  purple-team behavior;
- CISA Known Exploited Vulnerabilities for actively exploited advisories;
- NIST CSF 2.0, SP 800-61 Rev. 3, SP 800-115, and SP 800-92 for frameworks,
  incident response, security assessment, and log-management foundations;
- the repository's pinned community detection-rule corpus for threat detection and detection
  engineering.

Every embedded chunk includes a `CYBER:*` citation, publisher, license, trust
tier, retrieval time, and source hash. Unknown-license and unlicensed
proprietary data are rejected.

SANS and similar paid courseware are not included. To use organization-licensed
material, obtain written approval, mount it read-only, replace
`PROPRIETARY-LICENSE-REQUIRED` with the approved license identifier, and only
then enable the manifest entry.

## Ingest and refresh

```powershell
docker compose build kb-ingest mcp orchestrator
docker compose run --rm kb-ingest
```

`CYBER_CORPUS_REQUIRED=0` permits an air-gapped deployment to retain its last
good corpus when a refresh source is unavailable. Set it to `1` in a connected
CI or controlled refresh job when every required source must succeed.

## Hallucination controls

Ask THOS automatically invokes `search_cyber_knowledge` for general
cybersecurity questions. Explicit THOS product-support questions use the
separate product catalog; a question can receive both contexts when needed. A
cybersecurity response must cite only citation IDs returned by that call. If
retrieval is empty, citations are invented, or the model omits citations, THOS
withholds the claims and explicitly abstains.

Hunt reasoning also receives bounded cybersecurity excerpts, but these are
context only. They never prove that activity occurred; findings still require
citations to actual telemetry records.

## Evaluation gates

Run:

```powershell
python -m pytest -q tests/knowledge tests/evaluation tests/training
python -m services.evaluation.retrieval_eval data/evals/cybersecurity_retrieval.jsonl
python -m pytest -q
```

The initial retrieval set is
`data/evals/cybersecurity_retrieval.jsonl`. Expand it to at least 100
SME-reviewed questions, balanced across all curriculum domains, before
comparing embedding or reranking changes.

An optional weight-adaptation run is blocked until:

- at least 250 human-verified, evidence-cited examples exist;
- retrieval pass rate is at least 90%;
- grounding/abstention pass rate is at least 98%;
- the training GPU has at least 12 GB VRAM for a 4B QLoRA target;
- a cybersecurity SME approves the frozen dataset and eval snapshot.

The current 4 GB NVIDIA T600 is appropriate for quantized inference and RAG
evaluation, but it does not pass the 4B training gate. Use a separate on-prem
training machine; import only the approved adapter into the production Ollama
environment.

## Preparing fine-tuning records

`services/training/dataset_builder.py` accepts only examples with:

- `human_verified: true`;
- evidence from an enabled, approved manifest source;
- `CYBER:*` citations that occur in both the answer and evidence;
- a named verifier and curriculum domain.

Synthetic answers are never admitted automatically. Analyst corrections and
approved hunt findings can become candidates, but an SME must verify them
before they enter the training snapshot.

Fine-tune stable response behavior with LoRA/QLoRA; do not fine-tune volatile
threat intelligence. A candidate adapter must beat the frozen baseline,
complete a canary period, and retain a one-command rollback to the prior model.
