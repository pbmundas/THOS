# THOS Developer Guide
### AI-Powered Threat Hunting Platform — Onboarding & Scaling Reference

**Audience:** Engineers joining the THOS project who need to get productive quickly — understand the architecture, run it locally, extend it safely, and know where the sharp edges are.

---

## Table of Contents

1. [What THOS Is](#1-what-thos-is)
2. [Architecture Overview](#2-architecture-overview)
3. [Technology Stack](#3-technology-stack)
4. [Repository Structure](#4-repository-structure)
5. [The Hunt Lifecycle (Core Concept)](#5-the-hunt-lifecycle-core-concept)
6. [Service-by-Service Deep Dive](#6-service-by-service-deep-dive)
7. [Data & State Model](#7-data--state-model)
8. [Authentication & Security Model](#8-authentication--security-model)
9. [Local Development Setup](#9-local-development-setup)
10. [Configuration Reference (Environment Variables)](#10-configuration-reference-environment-variables)
11. [Observability: Logging, Audit, Caching, Retries](#11-observability-logging-audit-caching-retries)
12. [Testing](#12-testing)
13. [Extending THOS — Common Tasks](#13-extending-thos--common-tasks)
14. [Deployment (Docker Compose)](#14-deployment-docker-compose)
15. [Known Limitations & Gotchas](#15-known-limitations--gotchas)
16. [Roadmap](#16-roadmap)
17. [Quick Reference: File Map](#17-quick-reference-file-map)

---

## 1. What THOS Is

**THOS (Threat Hunting Operating System)** is an on-premises, AI-powered threat hunting platform for SOC analysts. Instead of writing raw SIEM queries, an analyst picks (or free-texts) a **hunting hypothesis** in a chat UI, and THOS autonomously:

1. Selects/refines the hypothesis and maps it to a MITRE ATT&CK technique
2. Generates a SIEM query for it
3. Fetches matching logs from a SIEM (or a local log folder)
4. Normalizes/parses those logs
5. Runs deterministic detection logic (community rules + custom detection rules + LLM-derived indicators) against them
6. Uses a local LLM (via Ollama) to reason over the evidence
7. Loops back for more logs if the LLM says it needs them
8. Writes a structured Markdown hunt report

Everything — LLM inference, vector search, log storage, report storage — runs **locally in Docker containers**, with no data leaving the environment. This matters for the target users (SOC teams in regulated/air-gapped environments).

---

## 2. Architecture Overview

THOS is a set of Dockerized microservices orchestrated by **LangGraph** (a state-machine/agent framework), talking to tools over **MCP (Model Context Protocol)**.

```
                         ┌─────────────────────┐
   Analyst  ──────────▶  │  Analyst UI (React)  │  :7860 (only public port)
                         └──────────┬───────────┘
                                    │ Bearer token (ORCHESTRATOR_API_KEY)
                                    ▼
                         ┌─────────────────────┐
                         │  Orchestrator API    │  FastAPI + LangGraph
                         │  (services/orchestration)
                         └──────────┬───────────┘
                                    │ MCP calls, Bearer token (MCP_AUTH_TOKEN)
                                    ▼
                         ┌─────────────────────┐
                         │   MCP Server         │  FastMCP tool registry
                         │  (services/api/server.py)
                         └───┬────────┬────────┬┘
                             │        │        │
                 ┌───────────┘   ┌────┘    ┌───┘──────────┐
                 ▼                ▼                        ▼
        ┌────────────────┐ ┌─────────────┐        ┌──────────────────┐
        │  Ollama (LLM)   │ │ ChromaDB     │        │ SIEM Connectors   │
        │  qwen3:4b     │ │ (vector RAG) │        │ mock/folder/      │
        └────────────────┘ └─────────────┘        │ LogRhythm/Splunk/  │
                                                     │ QRadar             │
                                                     └──────────────────┘
                             ┌─────────────┐  ┌─────────────┐
                             │ PostgreSQL  │  │   Redis     │
                             │ (audit log) │  │ (cache/rate)│
                             └─────────────┘  └─────────────┘
```

**Key architectural decisions to internalize:**

- **Chat UI never talks to the MCP server or the LLM directly.** It only calls the Orchestrator's REST API. The Orchestrator is the only client of the MCP server. This keeps a single, auditable choke point for every tool call.
- **The MCP server is the tool boundary.** Every capability — SIEM query, detection rule evaluation, report writing, KB search — is exposed as an `@mcp.tool()` function. LangGraph nodes never call SIEM/DB/LLM code directly; they call `call_tool("tool_name", {...})` over MCP. This is what makes the system's capabilities discoverable and independently testable.
- **LangGraph owns the control flow**, not application code. The hunt is a directed graph of nodes (see Section 5); adding/re-ordering steps means editing the graph definition, not scattering `if` statements through a monolith.
- **No service is safe to expose on the host network by default.** Only `chat-ui` publishes a host port (`7860`). Everything else communicates over the internal `thos-net` Docker network and is gated by a bearer token. This is deliberate — see Section 8.

---

## 3. Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| Analyst frontend | **React + Vite** | `services/ui/`, served by a session-gated FastAPI gateway |
| Backend API / orchestration | **FastAPI** + **LangGraph** | `services/orchestration/main.py`, `graph.py` |
| Tool execution layer | **FastMCP** (Model Context Protocol) | `services/api/server.py` |
| Local LLM inference | **Ollama**, default model `qwen3:4b` | No cloud calls |
| Vector database (RAG) | **ChromaDB** | Collections: `hearth_kb`, `mitre_kb` (implicit), `siem_kb`, `custom_kb` |
| Relational store | **PostgreSQL 16** | Audit trail: hunts, hunt_steps, tool_errors, reports |
| Cache / rate limiting | **Redis 7** | SIEM/LLM response caching, per-hunter rate limits |
| Detection engine | **Audited rule compiler** | Parses the vendored community corpus and custom rules |
| Log parsing | `python-evtx`, `scapy`, `pyyaml`, custom parsers | EVTX, PCAP, CSV, CEF, syslog, JSON/ECS, XML, etc. |
| Containerization | **Docker Compose** | One `docker-compose.yml`, per-service Dockerfiles |
| Language | **Python 3.12+** | Entire backend |
| Testing | **pytest**, `pytest-cov` | CI via GitHub Actions |

---

## 4. Repository Structure

```
.
├── docker-compose.yml          # Full stack definition — START HERE for infra
├── env.example                 # Copy to .env; every secret/tunable lives here
├── Dockerfile                  # (root-level, see note below)
├── db/init_db.sql              # Postgres schema (hunts, hunt_steps, tool_errors, reports)
├── requirements.txt            # Combined Python deps (also per-service requirements.txt)
├── pytest.ini / conftest.py    # Test configuration
├── data/
│   ├── knowledge_base/hearth/  # Seed data ingested into ChromaDB (hearth_full.json)
│   ├── log_sources/            # Sample EVTX files for "folder" mode hunts
│   └── reports/                # Generated Markdown hunt reports land here
├── services/
│   ├── orchestration/          # LangGraph state machine + FastAPI wrapper (the "brain")
│   │   ├── graph.py            #   node wiring / control flow
│   │   ├── state.py            #   HuntState TypedDict — the shared state schema
│   │   └── main.py             #   FastAPI app: /hunt, /hunt/stream, /hypotheses, /kb/*
│   ├── api/                    # MCP server + secured analyst UI gateway
│   │   ├── server.py           #   MCP tool registry (the "hands")
│   │   └── ui_gateway.py       #   login/session, API proxy, reports/PDF
│   ├── ui/                     # React/Vite analyst workspace
│   ├── mcp/                    # MCP client + SOC-tool orchestration node
│   │   ├── mcp_client.py       #   thin call_tool() wrapper used by every graph node
│   │   └── soc_tools.py        #   runs all 3 detection layers concurrently
│   ├── hunting/                # Hypothesis selection, query generation, HEARTH KB refresh
│   ├── siem/                   # SIEM abstraction layer + connectors + log parsers
│   ├── detection/               # Detection-rule engines, corpora, and rule generators
│   ├── knowledge/               # ChromaDB ingestion: HEARTH, MITRE, custom docs
│   ├── reasoning/               # LLM prompt + Ollama client
│   ├── reporting/               # Markdown report generation
│   └── observability/           # Logging, audit (Postgres), cache (Redis), retry helper
├── tests/                       # pytest suite (detection, mcp, siem)
└── .github/workflows/tests.yml  # CI: pytest --cov=services on every push/PR
```

**Rule of thumb for navigating:** if you're asking "what capability does the AI have," look in `services/api/server.py` (the tool registry). If you're asking "in what order do things happen," look in `services/orchestration/graph.py`. Everything else is an implementation detail one of those two files points to.

---

## 5. The Hunt Lifecycle (Core Concept)

This is the single most important thing to understand before touching any code. Every hunt is one execution of the compiled LangGraph state machine defined in `services/orchestration/graph.py`:

```
refresh_hearth_kb → hypothesis → query_gen → siem_fetch → log_processing
   → soc_tools → reasoning ──┬─→ (need_more_logs=true) → siem_fetch  [loop]
                              └─→ (need_more_logs=false) → report → END
```

| Node | File | Responsibility |
|---|---|---|
| `refresh_hearth_kb` | `services/hunting/kb_refresh.py` | Rate-limited (via Redis) re-fetch of hypotheses from the live HEARTH GitHub repo, so the KB doesn't go stale but also doesn't re-fetch on every single hunt |
| `hypothesis` | `services/hunting/hypothesis.py` | Resolves a `hypothesis_id` to full detail, or semantically searches for one from free text; maps to a MITRE ATT&CK technique |
| `query_gen` | `services/hunting/query_gen.py` → `query_generator.py` | LLM-assisted generation of a concrete SIEM query, grounded in the SIEM-specific field mapping (`siem_kb.py`) |
| `siem_fetch` | `services/siem/siem_fetch.py` → `siem_connector.py` | Executes the query against whichever SIEM backend is configured; returns raw records |
| `log_processing` | `services/siem/log_processing.py` | Normalizes raw records into the platform's 8-field schema |
| `soc_tools` | `services/mcp/soc_tools.py` | Runs **three detection layers concurrently** (see Section 6.5) against the normalized logs |
| `reasoning` | `services/reasoning/reasoning.py` | Sends hypothesis + histogram + sample records + detection rule matches + RAG context to the LLM; LLM produces findings/recommendations and decides `need_more_logs` |
| `report` | `services/reporting/report.py` | Writes the final Markdown report to `data/reports/` |

**The loop:** if the LLM's reasoning output sets `need_more_logs = true`, the graph routes back to `siem_fetch` (using `follow_up_query`) instead of proceeding to `report`. This is capped by `max_iterations` (default 1 to minimize latency; callers may explicitly raise it to 5). The deterministic verifier still runs after the single default reasoning pass, so invalid citations fail closed instead of relying on extra model calls.

**State propagation:** LangGraph merges each node's returned `dict` into a single shared `HuntState` (a `TypedDict` — see Section 7). Nodes only need to return the keys they set; they don't need to know about the rest of the state.

---

## 6. Service-by-Service Deep Dive

### 6.1 Orchestrator (`services/orchestration/`)

FastAPI service, port `8200` (internal only). Endpoints:

| Method & Path | Purpose |
|---|---|
| `GET /health` | Liveness check — the only unauthenticated endpoint |
| `GET /hypotheses?tactic=` | List HEARTH hypotheses, optionally filtered by MITRE tactic |
| `GET /hypotheses/last-runs` | Latest audit timestamp for every hypothesis that has been run |
| `GET /hunt/status` | Platform-wide active-hunt state used by the UI lock indicator |
| `POST /hunt` | Run a full hunt synchronously; returns final `HuntState` |
| `POST /hunt/stream` | Same, but streamed as newline-delimited JSON (one line per completed graph node) — this is what the chat UI uses for live progress |
| `GET /log_sources?folder=` | List log files in a candidate folder before running a "folder"-mode hunt |
| `POST /kb/upload`, `GET /kb/documents`, `DELETE /kb/documents/{id}`, `GET /kb/search` | Custom knowledge base (analyst-uploaded playbooks/runbooks) proxies |
| `POST /hypotheses/refresh` | Force a live re-fetch of HEARTH hypotheses, bypassing the Redis TTL |

**Operational safeguards worth knowing about (all in `main.py`):**
- **Per-hunter rate limiting** (`HUNT_RATE_LIMIT_PER_WINDOW`, default 10/60s) via `services/observability/cache.rate_limit_check`.
- **Single-hunt governance gate** (`_HuntSlot`): permits one platform-wide hunt and rejects a second start with HTTP 409 until the active hunt completes. The UI polls `/hunt/status`, disables every Run control, and displays a clear active-hunt notice.
- **Hunt-scoped logging context**: `set_hunt_context`/`reset_hunt_context` bind `hunt_id`/`hunter_name` to every log line emitted anywhere in that request's async call tree, without threading IDs through every function signature.

### 6.2 MCP Server (`services/api/server.py`)

FastMCP-based tool registry, port `8100` (internal only), auth via `StaticTokenVerifier` (`MCP_AUTH_TOKEN`). This is where **every** capability THOS has is declared as an `@mcp.tool()` function — hypothesis lookup, MITRE mapping, detection rule/YARA generation, SIEM query execution, custom KB CRUD, caching, and report I/O. See Section 13.1 for how to add a new one.

### 6.3 MCP Client (`services/mcp/mcp_client.py`)

Thin wrapper so any LangGraph node can do `await call_tool("tool_name", {...})` without managing connections. Key behaviors:
- Opens **one** streamable-HTTP session lazily, reused across all calls in the process (not one session per call).
- `asyncio.Lock`-guarded so concurrent hunts don't race to open duplicate sessions.
- On any exception, resets the client and retries **once** with a fresh session (covers server restarts / idle-timeout disconnects).

### 6.4 SIEM Layer (`services/siem/`)

`siem_connector.py` is the single entry point (`fetch_logs(query, limit, siem_type, log_source_path)`). It dispatches by `siem_type`:

| `siem_type` | Behavior | Implementation |
|---|---|---|
| `mock` | Synthetic records, no external dependency | inline in `siem_connector.py` |
| `folder` | Parses real log files from a local directory | `file_log_parser.py` |
| `logrhythm` | Live LogRhythm Web Console Search API (submit → poll → retrieve) | `logrhythm.py` |
| `splunk` | Live Splunk REST Search API (async search-job pattern) | `splunk.py` |
| `qradar` | Live IBM QRadar Ariel Search API (async AQL pattern) | `qradar.py` |
| `wazuh` | Live Wazuh Indexer search across alert/raw archive indices | `wazuh.py` |

All non-mock, non-folder connectors raise a dedicated `*ConfigError` (e.g. `LogRhythmConfigError`) when credentials are missing/incomplete, which `siem_connector.py` catches and turns into a structured `{"error": ...}` response instead of a raw stack trace bubbling up through MCP. **Follow this pattern for any new connector.**

Results for `folder`/`logrhythm`/`splunk`/`qradar`/`wazuh` are cached in Redis, keyed on the source configuration, query, and limit, so re-running the same hypothesis against the same source doesn't redo a full fetch/parse pass.

`file_log_parser.py` (572 lines — the largest single file) supports: EVTX, CSV, JSON/JSONL/NDJSON, XML, ECS JSON, syslog, CEF, LOG/TXT, PCAP/PCAPNG. It also enforces `LOG_SOURCE_ALLOWED_ROOTS` — any `log_source_path` passed at hunt time must resolve inside an allowed root, or the request is rejected (prevents arbitrary path reads).

`siem_kb.py` holds the **normalized ↔ vendor field mapping** per SIEM type — this is what `generate_siem_query` grounds its LLM prompt in, so generated queries use real field names for the target platform instead of hallucinated ones.

### 6.5 Detection Layer (`services/detection/`)

Three **independent, concurrently-executed** matching layers feed into `soc_tools.py`:

1. **Community detection-rule engine** — the reviewed community ruleset (~2,800+ rules, with its version pinned in `VERSION.txt`) is supplied from vendored files or a Compose persistent volume. Rules are parsed with the **audited rule compiler**, not a hand-rolled YAML parser; this provides correct nested boolean-condition and field-modifier handling. A custom `DictMatchBackend` walks the parsed condition tree and evaluates it directly against Python dictionaries.
2. **THOS custom engine** — approximately 16 hand-written, tuned rules for this platform's eight-field normalized schema. It is a high-precision supplementary layer, not a replacement for the community layer.
3. **LLM-derived indicators** (`indicator_deriver.py`) — for hypotheses/techniques neither static rule set covers, the LLM proposes candidate Event IDs + keywords, which are then substring-matched deterministically (not just trusted as free text).

**Known, explicitly-documented limitation:** the normalized schema only has eight generic fields (no structured `CommandLine`/`Image`/`ParentImage`/`GrantedAccess` extraction), so all three layers match against `event` plus substring/regex search inside the raw `detail` blob rather than fully parsed structured fields. Some community rules cannot be field-matched against this schema and are honestly skipped rather than approximated.

`indicator_deriver.py` and the detection-rule/YARA skeleton generators round out the module.

### 6.6 Knowledge / RAG Layer (`services/knowledge/`)

- `mitre.py` — local MITRE ATT&CK technique table (seeded from `services/knowledge/data/mitre_full.json`, generated by `_generate_mitre_full.py`).
- `hearth_fetch.py` / `fetch_hearth.py` — live-fetch HEARTH hypotheses from `https://github.com/THORCollective/HEARTH`, with graceful fallback if there's no route to GitHub (air-gapped deployments).
- `custom_kb.py` — the analyst-uploaded document pipeline (AnythingLLM-style): extracts text from txt/md/csv/json/log/html/pdf/docx, chunks with overlap, embeds into the `custom_kb` ChromaDB collection. Enforces `MAX_DOCUMENT_BYTES`.
- `ingest_knowledge_base.py` — the `kb-ingest` one-shot container's entrypoint, seeds ChromaDB from `data/knowledge_base/` on stack startup.
- Underlying vector client: `services/siem/clients.py` → `get_or_create_collection()` (shared by hearth/mitre/custom KB code — note this lives under `siem/`, a slightly misleading location worth knowing about).

### 6.7 Reasoning Layer (`services/reasoning/`)

`ollama_client.py` — minimal async wrapper around Ollama's `/api/generate` (or chat) endpoint.

`reasoning.py` (482 lines) — the largest "prompt" file in the repo and the **single place to tune analysis quality**. Notable design points:
- The system prompt explicitly treats all log-derived text (`detail`, `event`, `user`, `host`) as **untrusted, attacker-controllable data**, with instructions that any embedded prompt-injection attempt inside log data must be reported as a finding, never obeyed. This matters because log fields genuinely are adversary-controlled in a real intrusion.
- Includes a fixed reference table of Sysmon/Windows Event ID meanings, with an instruction to use *only* that table rather than the model's general knowledge — reduces hallucinated event-ID semantics.
- Provides an event-type histogram over the *full* processed log set (not just the sample shown), so the model can reason about absence of evidence across the whole dataset, and "ingestion diagnostics" (files scanned, records parsed, filter behavior) so it can distinguish "genuinely clean telemetry" from "we barely scanned anything."
- Decides `need_more_logs` / `follow_up_query`, driving the hunt loop back in `graph.py`.

### 6.8 Reporting (`services/reporting/report.py`)

Writes the final hunt report as Markdown to `REPORTS_DIR` (`data/reports/`), auto-deriving a short title from technique/tactic/hypothesis-id when none is given. Supports two cover styles: `"1"` = executive summary (management/compliance-facing), `"2"` = SOC analyst panel (technique/tactic/ingestion-stats table). `read_hunt_report` enforces that the requested path resolves inside `REPORTS_DIR` (`ReportPathError` on traversal attempts) — same defensive pattern as `LOG_SOURCE_ALLOWED_ROOTS`.

### 6.9 Analyst UI (`services/ui/`, `services/api/ui_gateway.py`)

The Vite-built React workspace presents all hypotheses as searchable/filterable
tiles. Every tile has Read and Run controls and shows its latest run date when
audit history exists. A platform-wide lock disables all Run controls while a
hunt is active. SMEs have a dedicated page for publishing governed custom
hypotheses; Analysts can read and run them but cannot create them. The UI also
streams timed hunt progress and renders stored Markdown reports with Markdown
and PDF downloads.
`ui_gateway.py` serves the compiled app, proxies only the required Orchestrator
operations using the server-side `ORCHESTRATOR_API_KEY`, authenticates the
SOCmate login form (`CHATUI_USERNAME`/`CHATUI_PASSWORD`, or `CHATUI_USERS`) into a
signed HTTP-only, SameSite session cookie, and generates PDF exports without
exposing the bearer token or credentials to browser JavaScript.

The same gateway owns the governed runtime control plane in
`services/api/control_plane.py`: PBKDF2-hashed SME/Analyst users, per-feature
permissions, Ollama model discovery/default selection, hypothesis and detection rule
schedules in `TZ`-configured local time, RAG document management, SIEM secrets
and field mappings, and the floating MCP-backed model assistant. Runtime values
are atomically persisted to `data/runtime/config.json`; all three runtime
services mount that directory, and `services/runtime_config.py` provides the
shared read path. Never commit that generated JSON file.

Final model reasoning is accepted only when it is non-empty, valid JSON, and
contains the complete required report fields. The node makes at most three
application-level attempts. If all three fail, THOS records every strike reason
and produces a citation-safe deterministic evidence analysis from detection rule,
telemetry, coverage, and enrichment results. That report is explicitly marked
as fallback analysis and requires human approval. Only a failure of both model
reasoning and the deterministic fallback ends without a report.

---

## 7. Data & State Model

### 7.1 `HuntState` (`services/orchestration/state.py`)

A `TypedDict(total=False)` — the contract every graph node reads from and writes partial updates to. Grouped by which node sets each field:

- **Request-provided:** `hunt_id`, `hunter_name`, `siem_type`, `log_source_path`, `log_limit`, `cover_style`, `max_iterations`
- **Set by `hypothesis`:** `hypothesis_id`, `hypothesis_text`, `technique_id`, `technique_name`, `tactic`
- **Set by `query_gen`:** `query`
- **Set by `siem_fetch`:** `logs`, `record_count`, `files_scanned`, `total_parsed`, `used_fallback_unfiltered`
- **Set by `log_processing`:** `processed_logs`
- **Set by `soc_tools`:** the draft rule, matched-count, matched-reference, matched-rule, and enrichment fields
- **Set by `reasoning`:** `reasoning_summary`, `findings`, `recommendations`, `need_more_logs`, `follow_up_query`
- **Set by `report`:** `report_path`
- **Bookkeeping:** `iteration`, `error`

When adding a new node, add whatever new fields it needs here first — LangGraph merges partial dict updates automatically, so nodes don't need to know about fields they don't use.

### 7.2 PostgreSQL Schema (`db/init_db.sql`)

| Table | Purpose |
|---|---|
| `hunts` | One row per hunt: hunter, hypothesis, status (`started`/`running`/`completed`/`failed`) |
| `hunt_steps` | One row per graph node execution: input/output JSONB, status, duration |
| `tool_errors` | Any tool/node error, with payload for debugging |
| `reports` | Generated report file paths + summaries, linked to `hunts` |

This is the audit trail — "what did the AI do, in what order, and why" — written by `services/observability/audit.py`. Extend it by adding a table per new feature that needs its own tracking.

### 7.3 ChromaDB Collections

| Collection | Populated by | Used by |
|---|---|---|
| `hearth_kb` | `kb-ingest` on startup, refreshed by `refresh_hearth_hypotheses` tool | `hypothesis` node's semantic search |
| `mitre_kb` (referenced conceptually) | `mitre.py` seed | technique mapping |
| `siem_kb` | seed JSON | field-mapping-grounded query generation |
| `custom_kb` | analyst uploads via `/kb/upload` | `search_knowledge_base` tool, injected as "organizational knowledge" context into reasoning |

---

## 8. Authentication & Security Model

THOS uses a **layered bearer-token model**, all with weak, well-known local-dev defaults that log a loud warning if left unchanged:

```
Analyst → [SOCmate login form → signed HTTP-only session cookie]
        → Analyst UI gateway → [Bearer: ORCHESTRATOR_API_KEY]
        → Orchestrator → [Bearer: MCP_AUTH_TOKEN]
        → MCP Server
```

- Every credential has a `thos_change_me_*` default so `docker compose up` works with zero setup, but each one gates real capability (running hunts, reading every report, calling SOC tools directly). **Generate real secrets (`openssl rand -hex 32`) before deploying beyond a trusted local dev box** — every service that uses a default logs a warning at startup as a reminder.
- Only `chat-ui` publishes a host port (`7860`). Ollama, ChromaDB, Postgres, Redis, MCP, and the Orchestrator are reachable **only** over the internal `thos-net` Docker network — deliberately not exposed to the host, even for "convenience."
- Redis requires a password (`REDIS_PASSWORD`) — it has no auth by default upstream.
- `/health` on the Orchestrator is the one deliberately unauthenticated endpoint, so container healthchecks work without a credential.
- Path traversal is guarded in two places: `LOG_SOURCE_ALLOWED_ROOTS` (folder-mode hunts) and `REPORTS_DIR` (report reads) — both reject paths that resolve outside their allowed root.
- The reasoning prompt explicitly treats log content as untrusted/attacker-controllable (see 6.7) — a deliberate prompt-injection defense given that log fields are adversary-influenced in real intrusions.

---

## 9. Local Development Setup

### Prerequisites
- Docker + Docker Compose
- (Optional, for GPU inference) NVIDIA Container Toolkit — without it, Ollama silently falls back to CPU, which is by far the biggest latency contributor for a 7B model
- Python 3.12+ if running services outside Docker for debugging

### Quick start (full stack)

```bash
git clone <repository-url>
cd thos
cp env.example .env
# edit .env — at minimum, configure SIEM_TYPE (defaults to real folder evidence)
docker compose up -d --build
```

Open `http://localhost:7860` and log in with `CHATUI_USERNAME`/`CHATUI_PASSWORD` (defaults: `analyst` / `thos_change_me`).

### Useful compose commands

```bash
docker compose logs -f orchestrator     # structured JSON logs, follow
docker compose logs -f mcp
docker compose ps                        # check healthchecks
docker compose down                      # stop, keep volumes
docker compose down -v                   # stop AND wipe vector DB / postgres / ollama data
```

### Running against local log files instead of mock data

Drop `.evtx`/`.log`/`.csv`/etc. files into `data/log_sources/` (already mounted into both `mcp` and `chat-ui`), set `siem_type: "folder"` on the hunt request (or select it in the chat UI), and point `log_source_path` at the folder.

### Running a single service outside Docker (debugging)

Each service under `services/*/` has its own `requirements.txt`. Install it, set the same env vars Docker would inject (see `docker-compose.yml`'s `environment:` blocks for the exact list per service), and run e.g.:

```bash
cd services/orchestration
pip install -r requirements.txt
uvicorn main:app --reload --port 8200
```

You'll still need `mcp`, `postgres`, `redis`, `ollama`, `chromadb` reachable — easiest is to run those via `docker compose up -d ollama chromadb postgres redis mcp` and point your local process's env vars at their published/mapped addresses.

---

## 10. Configuration Reference (Environment Variables)

All configuration lives in `env.example` → copy to `.env`. Highlights (see the file itself for the full annotated list, including per-connector tuning):

| Variable | Default | Purpose |
|---|---|---|
| `MCP_AUTH_TOKEN` | `thos_change_me_mcp_token` | Shared secret: orchestrator ↔ MCP server |
| `ORCHESTRATOR_API_KEY` | `thos_change_me_orchestrator_key` | Shared secret: chat-ui ↔ orchestrator |
| `CHATUI_USERNAME` / `CHATUI_PASSWORD` | `analyst` / `thos_change_me` | Single-hunter chat login |
| `CHATUI_USERS` | *(blank)* | Multi-hunter logins, `user:pass,user2:pass2`; overrides the single-user pair when set |
| `CHATUI_SESSION_SECRET` | `thos_change_me_session_key` | HMAC key for signed analyst sessions; replace in every non-local deployment |
| `CHATUI_SESSION_TTL_SECONDS` | `43200` | Analyst session lifetime (12 hours by default) |
| `CHATUI_SECURE_COOKIE` | `0` | Set to `1` when the UI is served through HTTPS |
| `REDIS_PASSWORD` | `thos_change_me_redis` | Redis auth |
| `OLLAMA_MODEL` | `qwen3:4b` | Swap to `qwen2.5:14b` for better reasoning quality (needs more RAM/VRAM) |
| `POSTGRES_USER/PASSWORD/DB` | `thos` / `thos_change_me` / `thos_audit` | Audit DB credentials |
| `SIEM_TYPE` | `folder` | `folder` \| `logrhythm` \| `splunk` \| `qradar` \| `wazuh` \| `elasticsearch`; `mock` is isolated-test-only and fails closed unless `ALLOW_SYNTHETIC_TELEMETRY=1` |
| `ALLOW_SYNTHETIC_TELEMETRY` | `0` | Keep `0` outside isolated development tests; prevents mock records from entering hunts or reports |
| `LOG_SOURCE_DIR` / `LOG_SOURCE_ALLOWED_ROOTS` | `/data/log_sources` | Folder-mode default + path-traversal allowlist |
| `LOGRHYTHM_BASE_URL` / `LOGRHYTHM_API_TOKEN` | *(blank)* | Required for `SIEM_TYPE=logrhythm` |
| `SPLUNK_BASE_URL` / `SPLUNK_TOKEN` | *(blank)* | Required for `SIEM_TYPE=splunk` |
| `QRADAR_BASE_URL` / `QRADAR_TOKEN` | *(blank)* | Required for `SIEM_TYPE=qradar` |
| `WAZUH_INDEXER_URL` / `WAZUH_INDEXER_USERNAME` / `WAZUH_INDEXER_PASSWORD` | *(blank)* | Required for `SIEM_TYPE=wazuh`; queries the Indexer on port 9200, not the manager API on port 55000 |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`, applies to orchestrator/mcp/chat-ui structured logs |
| `HUNT_RATE_LIMIT_PER_WINDOW` / `HUNT_RATE_LIMIT_WINDOW_SECONDS` | `10` / `60` | Per-hunter rate limit |
| `*_CPU_LIMIT` / `*_MEM_LIMIT` (per service) | varies | Docker Compose resource limits, tunable per deploy |

Every SIEM connector also has optional tuning env vars (SSL verification, lookback window, poll interval/timeout) — see the connector's own module (`logrhythm.py`/`splunk.py`/`qradar.py`) for the full list.

---

## 11. Observability: Logging, Audit, Caching, Retries

All under `services/observability/`:

- **`logging_config.py`** — attaches one structured-JSON stdout handler to the root logger (`configure_logging(service_name)`), called as early as possible in `orchestration/main.py` and `api/server.py`. Also provides `set_hunt_context`/`reset_hunt_context` (contextvars-based) so `hunt_id`/`hunter_name` are automatically attached to every log line in that request's async call tree. **Note:** `chat-ui`'s Docker build only copies `app.py`, so it reimplements an equivalent JSON formatter inline rather than importing this module — keep both in sync if you change the log line format.
- **`audit.py`** — writes every hunt start/step/completion/error to Postgres (see schema in 7.2). Deliberately **fails soft**: a broken audit write is logged, never raised, so it can't take down a live hunt. Uses a `psycopg_pool.ConnectionPool` (not a single shared connection) so concurrent hunts don't corrupt each other's sync-driver state.
- **`cache.py`** — Redis-backed `cache_get`/`cache_set` (SHA-256-keyed, namespaced, default 15-min TTL) and `rate_limit_check`. Used by `siem_connector.py` (repeated queries) and the rate limiter in `orchestration/main.py`.
- **`retry.py`** — shared retry/backoff for transient network failures (connection drops, timeouts, 5xx). Deliberately does **not** retry 4xx errors — a bad token or malformed request won't fix itself on attempt two. Two flavors: async (Ollama, MCP) and sync (LogRhythm, GitHub tarball fetch).

---

## 12. Testing

```bash
pip install -r requirements-dev.txt   # installs requirements.txt + pytest + pytest-cov
pytest --cov=services --cov-report=term-missing
```

Current test coverage (`tests/`):
- Detection-engine tests — community-rule parsing and deterministic evaluation
- `tests/mcp/test_soc_tools.py` — the concurrent 3-layer detection node
- `tests/siem/test_{logrhythm,qradar,splunk}_normalize.py` — connector response normalization

CI (`.github/workflows/tests.yml`) runs this same command on every push/PR to `main`/`master` via GitHub Actions, Python 3.12. **When adding a new SIEM connector or detection layer, add a corresponding test module under `tests/` following the existing naming/location pattern** — CI coverage is currently concentrated on detection and SIEM normalization, so those are the areas most protected against regressions; other areas (orchestration, reporting, knowledge ingestion) currently rely on manual verification.

---

## 13. Extending THOS — Common Tasks

### 13.1 Add a new MCP tool (new AI capability)

1. Implement the logic in the relevant `services/<domain>/` module.
2. In `services/api/server.py`, import it and wrap it with `@mcp.tool()`, following the existing pattern (docstring becomes the tool description the LLM/orchestrator sees).
3. Nothing else needs to change — the orchestrator discovers tools dynamically via MCP's `list_tools`. Call it from a graph node with `await call_tool("your_tool_name", {...})`.

### 13.2 Add a new SIEM connector

Follow the `logrhythm.py` / `splunk.py` / `qradar.py` pattern:
1. Create `services/siem/<vendor>.py` implementing `fetch_logs(query, limit) -> dict` and a `<Vendor>ConfigError` exception for missing/incomplete config.
2. Register it in `services/siem/siem_connector.py`'s `fetch_logs()` dispatch (add the `siem_type` branch, cache-key it the same way as the existing connectors).
3. Add the vendor's field mapping to `siem_kb.py` so query generation is grounded correctly.
4. Add connection env vars to `env.example` and document them.
5. Add a normalization test under `tests/siem/test_<vendor>_normalize.py`.

### 13.3 Add/modify a LangGraph node (change the hunt workflow)

1. Write the node as an `async def your_node(state: HuntState) -> dict` returning only the state keys it sets.
2. Add any new fields it reads/writes to `services/orchestration/state.py`'s `HuntState`.
3. Wire it into `services/orchestration/graph.py`: `graph.add_node(...)` + `graph.add_edge(...)` (or `add_conditional_edges` for branching, following the `route_after_reasoning` pattern).

Documented extension points already called out in the codebase: a human-approval gate before `report`, parallel fan-out to multiple SOC tools, or an "escalate" node for low-confidence hunts.

### 13.4 Add custom detection rules

- **Community ruleset refresh:** use the repository's detection-corpus fetch utility with a reviewed commit reference. The operation updates `VERSION.txt`. If no vendored YAML is present, Compose's one-shot rule initializer downloads the pinned commit into the persistent rule volume. MCP and Orchestrator mount that same volume and refuse to start until the pinned version and configured minimum count pass preflight.
- **THOS custom rules:** add a new `.yml` file to the local detection-rule directory following the existing rule format; the custom engine loads the directory automatically.

### 13.5 Tune LLM reasoning quality

Edit `SYSTEM_PROMPT` in `services/reasoning/reasoning.py` — it's the single place controlling analysis depth/style. See the inline comments there for specific levers (requiring host/user/timestamp citations, raising/lowering findings length, adding a confidence field, etc.).

### 13.6 Add a new knowledge source to RAG

Follow `hearth_fetch.py`'s pattern for a new external source, or extend `custom_kb.py` if it's an analyst-uploaded-document type problem instead. Either way, ingested content lands in a ChromaDB collection via `services/siem/clients.get_or_create_collection()`.

---

## 14. Deployment (Docker Compose)

`docker-compose.yml` defines 10 services with explicit `deploy.resources.limits` (CPU/memory, all env-overridable) and `healthcheck`/`depends_on` readiness chains so services don't start against dependencies that aren't ready yet:

1. **ollama** — LLM inference; GPU reservation via NVIDIA Container Toolkit (set `OLLAMA_GPU_COUNT=0` or remove the `deploy.resources.reservations` block on CPU-only hosts)
2. **ollama-model-init** — one-shot: pulls `OLLAMA_MODEL` with retries; **fails the whole startup** if the pull never succeeds, rather than letting `mcp`/`orchestrator` start against a model that silently 404s at hunt time
3. **chromadb** — vector store
4. **kb-ingest** — one-shot: seeds ChromaDB from `data/knowledge_base/`
5. **postgres** — audit DB, schema auto-applied from `db/init_db.sql` on first init
6. **redis** — cache/rate-limit store, password-protected
7. **Community-rule initializer** — one-shot: copies reviewed vendored rules or downloads the pinned commit; fails startup when fewer than the configured minimum are available
8. **mcp** — tool server, depends on chromadb/redis/postgres (all healthy) plus completed model and community-rule initialization
9. **orchestrator** — LangGraph engine, depends on mcp (started) + ollama (healthy) + ollama-model-init (completed) + postgres (healthy)
10. **chat-ui** — the only service with a published host port (`7860:7860`)

**Volumes** for models, ChromaDB, PostgreSQL, Redis, and community detection rules persist across restarts; `docker compose down -v` wipes all of them — use deliberately, not habitually. Removing the community-rule volume means the initializer must copy or download the corpus again.

**Resource tuning:** every limit (`OLLAMA_CPU_LIMIT`, `OLLAMA_MEM_LIMIT`, `CHROMA_CPU_LIMIT`, etc.) is overridable in `.env` per deployment — the defaults assume a modest single-host deployment, not a production sizing recommendation.

---

## 15. Known Limitations & Gotchas

These are explicitly acknowledged in the codebase's own comments/docstrings — worth knowing before you "rediscover" them:

- **8-field normalized log schema.** No structured `CommandLine`/`Image`/`ParentImage`/`GrantedAccess` extraction. All detection layers substring/regex-match against the raw `detail` blob. Some community rules are honestly unmatchable against this schema rather than approximated.
- **Single-model, likely single-GPU Ollama.** Realistically serves one inference request at a time on typical hardware — this is *why* the concurrency gate in `orchestration/main.py` exists. Don't remove it without addressing the underlying contention.
- **ChromaDB has no auth of its own** in this stack — it relies entirely on not being reachable outside `thos-net`. Don't add a host port binding for "convenience" without adding auth in front of it.
- **`chat-ui` doesn't share `services/observability/logging_config.py`** (single-file Docker build) — its JSON log formatter is a hand-duplicated equivalent in `app.py`. Keep them in sync manually if the log schema changes.
- **`get_or_create_collection` lives under `services/siem/clients.py`**, not `services/knowledge/`, despite being used by hearth/mitre/custom KB code — a naming/location quirk worth knowing when searching for it.
- **Weak default secrets everywhere** (`thos_change_me_*`). They're intentional for zero-friction local dev, but every one of them logs a startup warning and must be replaced before any non-trusted-local-network deployment.
- **Root-level `data/version/` folder** contains a `Backup.zip` and an `Improvements Required.docx` — these look like local working artifacts rather than part of the shipped application; confirm with the team whether they should be in version control before relying on them as up-to-date documentation.

---

## 16. Roadmap

Per the project README, upcoming/planned work includes: Microsoft Sentinel, Elastic Security, Google Chronicle, and Cortex XSIAM connectors; YARA rule generation and IOC enrichment; threat-intel integration; SOAR playbooks; scheduled hunts; investigation timelines; case management; multi-user collaboration; and autonomous AI hunting agents. New contributors looking for a well-scoped first task should look at **13.2 (new SIEM connector)** — the pattern is well-established and the next four connectors are already named.

---

## 17. Quick Reference: File Map

| I want to... | Look at... |
|---|---|
| Understand the end-to-end hunt flow | `services/orchestration/graph.py` |
| See/change what state flows between steps | `services/orchestration/state.py` |
| Add a new AI-callable tool | `services/api/server.py` |
| Add/modify a SIEM integration | `services/siem/siem_connector.py` + new `services/siem/<vendor>.py` |
| Change how the LLM reasons/writes findings | `services/reasoning/reasoning.py` |
| Add/tune detection rules | Local detection-rule directory (custom) or the repository's corpus-fetch utility (community) |
| Change report format/content | `services/reporting/report.py` |
| Change analyst UI behavior | `services/ui/src/App.jsx`, `services/ui/src/Settings.jsx`, `services/ui/src/ChatPage.jsx`, `services/ui/src/app.css` |
| Change UI auth/API proxy/PDF export | `services/api/ui_gateway.py` |
| Change settings, users, schedules, RAG, or SIEM forms | `services/api/control_plane.py`, `services/runtime_config.py` |
| Change the read-only MCP model chatbot | `services/chat_agent.py`, `services/ui/src/ChatPage.jsx` |
| Change auth / rate limits / concurrency | `services/orchestration/main.py` |
| Change logging/audit/caching behavior | `services/observability/*.py` |
| Change infra topology, ports, resource limits | `docker-compose.yml` |
| Change env var defaults/docs | `env.example` |
| Change the audit DB schema | `db/init_db.sql` |
| Add a test | `tests/<domain>/test_*.py`, run via `pytest.ini`/`conftest.py` |

---

*This guide reflects the state of the codebase as extracted from the provided repository archive. As THOS evolves, keep this document's Section 13 (extension patterns) and Section 15 (known limitations) up to date — they age fastest.*
