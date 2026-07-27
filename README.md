# THOS – AI-Powered Threat Hunting Platform

<p align="center">

**AI-Powered • Hypothesis-Driven • Multi-SIEM • RAG • LangGraph • MCP • Fully On-Premises**

</p>

---

## Overview

**THOS (Threat Hunting Operating System)** is an enterprise-grade, AI-powered threat hunting platform designed to help SOC Analysts, Threat Hunters, and Incident Responders investigate security events using natural language.

Unlike traditional SIEM search interfaces, THOS enables analysts to perform **hypothesis-driven threat hunting** through an interactive chat interface. Behind the scenes, THOS orchestrates multiple AI agents using **LangGraph**, retrieves contextual knowledge through **Retrieval-Augmented Generation (RAG)**, integrates with multiple SIEM platforms, analyzes telemetry using local Large Language Models (LLMs), and automatically generates comprehensive threat hunting reports.

THOS is designed to operate **entirely on-premises**, ensuring sensitive security data never leaves your environment.

---

# Key Features

- 🤖 AI-powered hypothesis-based threat hunting
- 💬 Interactive chat interface for SOC Analysts
- 🧠 Local LLM inference using Ollama (offline capable)
- 🔗 LangGraph multi-agent orchestration
- 🧩 FastMCP modular tool execution
- 📚 Retrieval-Augmented Generation (RAG)
- 🗄️ ChromaDB vector knowledge base
- 🛡️ Multi-SIEM integration
- 📂 Folder-based log hunting
- 🔍 Automatic log parsing and normalization
- 📖 MITRE ATT&CK & HEARTH framework integration
- 📄 Automated Markdown hunting reports
- ⚡ FastAPI backend services
- 🖥️ Responsive React analyst workspace with hypothesis tiles and report library
- ⚙️ Governed Settings control plane for models, iterations, Sigma, SIEM schemas, schedules, RAG, and local users
- 💬 Floating on-prem model assistant with minimize/maximize controls and an audited read-only MCP tool allowlist
- 🐳 One-command Docker deployment
- 🔒 Fully on-premises architecture

---

# Architecture

<img width="50%" alt="ChatGPT Image Jul 8, 2026, 11_17_41 PM" src="https://github.com/user-attachments/assets/39ecbf05-df8d-498a-9d2a-b3b22676def5" />



---

# Core Components

| Component | Description |
|------------|-------------|
| **React UI** | Searchable hypothesis board, streamed hunt progress, and report library |
| **FastAPI** | REST API backend |
| **LangGraph** | AI workflow orchestration |
| **FastMCP** | Tool execution framework |
| **Ollama** | Local Large Language Models |
| **ChromaDB** | Vector database for semantic retrieval |
| **Knowledge Base** | MITRE ATT&CK & HEARTH frameworks |
| **Parser Engine** | Multi-format log normalization |
| **SIEM Connectors** | Unified interface for multiple SIEM platforms |
| **Report Engine** | Automated Markdown report generation |
| **PostgreSQL** | Metadata and audit storage |
| **Redis** | Caching and task management |

---

# Supported SIEM Platforms

THOS provides a modular SIEM abstraction layer, allowing the same AI hunting workflow to operate across different security platforms.

| SIEM Platform | Status | Integration |
|---------------|--------|-------------|
| Folder Logs | ✅ Supported | Local Filesystem |
| Mock Data | ✅ Supported | Built-in Simulator |
| LogRhythm | ✅ Supported | Search API |
| Splunk Enterprise | ✅ Supported | REST Search API |
| Splunk Cloud | ✅ Supported | REST Search API |
| IBM QRadar | ✅ Supported | Ariel Search API |
| Wazuh | ✅ Supported | Wazuh Indexer / OpenSearch Search API |

Additional SIEM platforms can be integrated by implementing a new connector within the `services/siem` module.

---

## Wazuh Indexer log source

THOS queries security telemetry from the Wazuh Indexer API on port `9200`;
it does not use the Wazuh manager API on port `55000`. For the accompanying
Docker Desktop purple-team lab, configure `.env` with the Indexer credentials
from that lab:

```dotenv
WAZUH_INDEXER_URL=https://host.docker.internal:9200
WAZUH_INDEXER_USERNAME=<read-only-indexer-user>
WAZUH_INDEXER_PASSWORD=<password>
WAZUH_INDEX_SOURCE=both
WAZUH_VERIFY_SSL=0
```

`WAZUH_INDEX_SOURCE=both` searches `wazuh-alerts-*` and
`wazuh-archives-*`. Disabling TLS verification is appropriate only for the
isolated self-signed local lab. For other deployments, leave verification
enabled and provide the Wazuh root CA through `WAZUH_CA_BUNDLE`. Rebuild the
`mcp` service after changing its environment, then select `wazuh` in the
Target SIEM dropdown.

---

# Supported Log Formats

THOS supports automatic parsing and normalization of multiple security log formats.

| Format | Support |
|----------|----------|
| EVTX | ✅ |
| CSV | ✅ |
| JSON | ✅ |
| JSONL | ✅ |
| NDJSON | ✅ |
| XML | ✅ |
| ECS JSON | ✅ |
| Syslog | ✅ |
| CEF | ✅ |
| LOG | ✅ |
| TXT | ✅ |
| PCAP | ✅ |
| PCAPNG | ✅ |

Default ingestion directory:

```text
data/log_sources/
```

---

# Threat Hunting Workflow

```text
Analyst Hypothesis
        │
        ▼
Select Target SIEM
        │
        ▼
Retrieve Security Events
        │
        ▼
Normalize & Parse Logs
        │
        ▼
RAG Knowledge Retrieval
        │
        ▼
LLM Threat Analysis
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Generate Threat Hunting Report
```

---

# Technology Stack

| Layer | Technology |
|--------|------------|
| Frontend | React + Vite |
| Backend | FastAPI |
| AI Workflow | LangGraph |
| MCP Framework | FastMCP |
| Local LLM | Ollama |
| Default Model | Qwen3.4B |
| Vector Database | ChromaDB |
| Database | PostgreSQL |
| Cache | Redis |
| Knowledge Base | MITRE ATT&CK & HEARTH |
| Containerization | Docker Compose |
| Programming Language | Python 3.12+ |

---

# Quick Start

```bash
# Clone the repository
git clone <repository-url>

cd thos

# Configure environment
cp env.example .env

# Start all services
docker compose up -d --build
```

Open your browser:

```
http://localhost:7860
```

---

# Generated Reports

Every investigation produces a structured Markdown report containing:

- Executive Summary
- Threat Findings
- Evidence
- MITRE ATT&CK Mapping
- Indicators of Compromise (IOCs)
- Recommendations
- Analyst Notes

Reports are automatically saved to:

```text
data/reports/
```

The report library renders that Markdown directly and provides both the original
`.md` file and a styled PDF export. Reports are written only after reasoning
returns a complete, schema-valid result. An empty, malformed, or truncated model
response is retried up to three total attempts. If all three fail, THOS records
the strike reasons and completes a clearly marked deterministic evidence report
that requires human approval; an unfinished model response is never published.

## Settings and local roles

The first configured UI account is seeded as the **SME administrator**. SMEs can
select any model already available in Ollama, choose the default hunt iteration
count, enable/disable and schedule Sigma rules, schedule hypotheses in system
local time, configure SIEM credentials and normalized vendor fields, manage the
RAG knowledge base, and create local users. Analyst accounts see only the
features assigned by an SME (`hunts`, `reports`, `chat`, and/or `knowledge`).

Each hypothesis tile includes a full Read view, a Run action, and its most
recent run date when audit history is available. THOS permits one active hunt
across the platform; all other Run actions remain disabled with a visible
status notice until it completes. Only SME administrators can publish custom
hypotheses from the dedicated **Create hypothesis** page.

Settings are persisted in `data/runtime/config.json` and consumed dynamically by
the UI gateway, Orchestrator, and MCP service. The file is deliberately ignored
by Git because it can contain password hashes and SIEM secrets. Back it up as a
secret and restrict filesystem access in production.

---

# Security

THOS is built for security-conscious environments.

- Fully on-premises deployment
- Local AI inference (no cloud model dependency)
- Local vector database
- Local report storage
- Suitable for regulated and air-gapped environments

SigmaHQ rules are loaded from a persistent `sigmahq_rules` volume. On
startup, Compose first copies a reviewed corpus from
`services/detection/sigma_rules_hq/`. If the repository contains only the
version marker, the one-shot `sigmahq-rules-init` service downloads the exact
commit configured by `SIGMAHQ_REF` and verifies at least
`SIGMAHQ_MIN_RULES` rules before MCP or the Orchestrator can start. Both
services mount the same read-only corpus and run a fail-fast preflight, so SOC
tools cannot silently fall back to `0 SigmaHQ rules`. For air-gapped deployment,
run `python services/detection/fetch_sigmahq_rules.py --ref <commit>` on a
connected review machine and commit the resulting directory.

YARA follows the same governed corpus lifecycle. The one-shot
`yararules-init` service populates a persistent volume from the exact
`YARARULES_REF` commit of
[`Yara-Rules/rules`](https://github.com/Yara-Rules/rules), and
`yara-catalog-init` validates each upstream file before building one reusable
compiled database. Compatible files remain available even when a legacy rule
uses an unsupported module field or has invalid syntax; incompatible files are
quarantined with their compiler error in the Configuration catalog. MCP,
Orchestrator, and the UI mount the same read-only corpus and compiled catalog.
Rules can be searched, severity-filtered, enabled/disabled, manually scanned,
or scheduled. `YARARULES_MIN_FILES` and `YARARULES_MIN_READY_RULES` are
fail-fast startup invariants. For offline deployment, place a reviewed corpus
and matching `VERSION.txt` under
`services/detection/yara_rules_community/`.

Hunts execute independently of the browser stream and therefore continue when
an analyst reloads or navigates away. Every run is retained in PostgreSQL with
its last stage, terminal status, report path, and failure reason. The Reports
page exposes this run history. Reasoning still validates up to three model
responses; if all fail, a citation-safe deterministic evidence analysis creates
the report and requires human approval instead of silently losing the hunt.

---

# Roadmap

Upcoming enhancements include:

- Microsoft Sentinel Connector
- Elastic Security Connector
- Google Chronicle Connector
- Cortex XSIAM Connector
- Sigma Rule Generation
- IOC Enrichment
- Threat Intelligence Integration
- SOAR Playbooks
- Scheduled Hunts
- Investigation Timeline
- Case Management
- Multi-user Collaboration
- Autonomous AI Hunting Agents

---

# Agentic Phase 2 APIs

The orchestrator now exposes authenticated case, approval, and analyst-feedback APIs:

- `GET` / `POST /cases`, `PATCH /cases/{case_id}`
- `POST /approvals/{approval_id}/decision` (`approved` or `rejected`)
- `POST /feedback` (`up`, `down`, or `corrected`)

Verifier failures automatically create a pending approval and high-priority case.
For an existing Postgres volume, apply the migration once:

```bash
docker compose exec -T postgres psql -U thos -d thos_audit < db/migrations/002_agentic_cases.sql
```

# Agentic AI Capabilities

THOS remains fully on-premises and now extends its original hunt pipeline with:

- **Supervisor and Hunt Memory:** uses a structured local-model plan, recalls comparable completed hunts, and can make one bounded query refinement from intermediate findings.
- **Layered Guardrail, Verifier, and Human Review:** canonicalizes encoded telemetry, sends ambiguous content to a dedicated adversarial classifier, quarantines high-risk reasoning fields, verifies citations, and records approval/case workflows.
- **ATT&CK Coverage, IOC, and Anomaly Agents:** map required ATT&CK data sources to observed device/event categories, match IOCs only against a local blocklist (`data/threat_intel/blocklist.json`), and surface rare event types.
- **Detection Engineering:** creates experimental detection-rule proposals for verifier-passed coverage gaps; approval can stage them in `data/detection_rule_proposals/`, never directly in live rules.
- **Communication and Learning:** prepares audience-aware report summaries and captures analyst feedback. Export labelled examples with `GET /learning/feedback-export` for offline on-prem evaluation or fine-tuning.
- **Performance Metrics:** `GET /hunts/{hunt_id}/metrics` reports per-node timings from the audit trail.

## Schema-aware scheduled detection pipeline

THOS now uses one shared `discover -> cache -> compile -> run -> triage` path
for continuous Sigma coverage:

1. Every active live SIEM is sampled with a bounded read-only query. THOS
   inventories fields from the connector's retained raw vendor payload, infers
   types, redacts secret-like sample values, and stores a versioned snapshot in
   Redis.
2. The new snapshot is diffed against the prior one. Added, removed, and
   type-changed fields remain visible as schema drift instead of being silently
   overwritten. A stale snapshot remains usable when the weekly refresh fails.
3. Sigma rules are recompiled against the discovered schema. Splunk and Wazuh
   use the audited pySigma backends bundled by this repository. QRadar and
   LogRhythm remain fail-closed until audited backends are added; rules with
   missing fields are reported as uncompilable rather than silently skipped.
4. Scheduled rules execute their cached native queries without an LLM. Repeated
   hits are fingerprinted in Redis, so only new events create a formal detection
   case. Triage is deterministic from Sigma and local MITRE metadata, preserving
   GPU capacity for analyst reasoning.

The gateway runs schema discovery and compilation every seven days for
connection-tested live SIEMs. SMEs can also trigger the same governed operation
from **Integrations > SIEM > Available SIEM log fields**. Manual one-column CSV
inventories remain available for air-gapped or least-privilege deployments that
do not allow sample queries.

All agentic write paths are approval-gated or confined to staging. The live detection ruleset is never modified automatically.

## Testing all agents and Ask THOS product knowledge

THOS now keeps every runtime agent in a canonical registry and validates the
registry against its implementation, LangGraph node, and regression-test
mapping. The first check has no service or model dependency:

```powershell
.\scripts\test-agents.ps1 contracts
```

Run focused offline behavior and product-knowledge tests with:

```powershell
.\scripts\test-agents.ps1 offline
```

Run the complete regression suite with `.\scripts\test-agents.ps1 full`. After
the Docker stack is running, use `.\scripts\test-agents.ps1 live` and complete
the evidence-driven acceptance scenarios in
[`docs/AGENT-TESTING.md`](docs/AGENT-TESTING.md).

Ask THOS no longer depends on model memory for THOS product facts. It receives
a versioned built-in product catalog on every product question, cites `PK-*`
source identifiers, keeps uploaded organizational documents as a separate RAG
source, and exposes the selected product sources in chat responses. Ask THOS is
routed to the dedicated fast-tier local model so routine product and SOC
questions do not consume the larger hunt-reasoning tier.

Ask THOS is also an authorized investigation-assistance agent. It can read
persisted hunt and forensic state, agent stages, model metadata, and reports
according to the signed-in user's role. Detailed evidence questions are
delegated to the Hunt Investigation Specialist or Digital Forensic Specialist;
the UI records the delegated agent, model tier/name, and duration.

## Digital forensic examination

The **Forensics** menu accepts one or more logs, archives, documents, packet
captures, disk images, or other evidence files. Original uploads are retained
under `data/log_sources/forensic/<UTC date>/<date-serial-case>/`. Intake records
the collector/tool, legal authority, original and stored names, size, and
SHA-256 in a chain-of-custody manifest. Full-file size and hash are independently
verified before analysis; any mismatch fails the case closed.

The Forensic Intake, Artifact Analysis, Detection Correlation, Timeline, and
Reporting agents run sequentially with persisted names, activities, durations,
and model metadata. These integrity-sensitive stages are deterministic and do
not use a language model. Known logs use the same normalized analysis path as
active SIEM hunts; unknown files receive bounded artifact triage. The
orchestrator image includes `ewf-tools` and Sleuth Kit for E01/Ex01 and raw-image
metadata. Enabled local and pinned community YARA rules scan managed evidence
from a precompiled catalog with file-size, file-count, match-count, and timeout
limits. Reports include suspicious or corroborated malicious activity
assessments and a classification-aware timeline. Missing or proprietary
decoders are recorded as limitations.

The **Reports** page separates Hunt and Forensic records. Administrators can
remove either report from the active library; removal is recoverable from the
server-side `.trash` archive.

## Security integrations and mixed-source attribution

The **Integrations** page is the single configuration surface for SIEM,
EDR/XDR, identity, cloud, email/SaaS, network/NDR, and generic JSON security
sources. Direct integrations use a bounded read-only connector with server-side
Bearer, API-key, Basic, or OAuth2 client-credential handling. Only successfully
tested sources become selectable for hunts and schedules.

When a SIEM query returns heterogeneous records, THOS adds source vendor,
product, device type, event category, confidence, and attribution basis to each
normalized record. Coverage assessment uses those fields together with the
selected technique's ATT&CK data-source requirements.

## Governed cybersecurity knowledge and model adaptation

THOS uses a license-controlled cybersecurity corpus for MITRE ATT&CK, CISA KEV,
NIST incident-response/framework/logging guidance, and the pinned SigmaHQ rule
set. Each retrieved excerpt carries a `CYBER:*` citation and provenance.
Ask THOS withholds uncited cybersecurity claims, and hunt reasoning treats
external knowledge as context rather than proof of activity.

The model-adaptation workflow intentionally keeps volatile intelligence in RAG
and fine-tunes only stable behaviors after human verification and evaluation
gates. See
[`docs/CYBERSECURITY-MODEL-ADAPTATION.md`](docs/CYBERSECURITY-MODEL-ADAPTATION.md).

## Agentic Configuration

`env.example` includes model tiers, follow-up limits, and timeout settings. The
default keeps one adaptive follow-up query. Final reasoning follows an
application-level three-strike rule: exactly three complete-response attempts,
then a clear `report not generated` failure rather than a degraded report.
Rebuild after changing configuration:

```bash
docker compose up -d --build
```

# Contributing

Contributions are welcome!

Whether you're adding new SIEM connectors, improving AI workflows, expanding knowledge sources, or fixing bugs, feel free to submit a pull request.

---

# License

This project is licensed under the **MIT License** (or your preferred license).

---

# Acknowledgements

THOS is built upon several outstanding open-source technologies:

- Ollama
- LangGraph
- FastMCP
- ChromaDB
- FastAPI
- React
- Vite
- PostgreSQL
- Redis
- Docker
- MITRE ATT&CK Framework
- HEARTH Threat Hunting Framework

---

# Disclaimer

THOS is intended for authorized security monitoring, threat hunting, incident response, and cybersecurity research. Users are responsible for ensuring compliance with all applicable laws, regulations, and organizational policies before deploying or using this software.
