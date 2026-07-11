# THOS → Agentic AI Platform: Implementation Plan

### From fixed-pipeline tool orchestration to a supervised multi-agent SOC platform

**Purpose of this document:** a phased, trackable engineering plan to convert THOS's current `services/*` tool layer + fixed LangGraph pipeline into a true multi-agent architecture, and to scale that architecture for enterprise threat hunting. Every feature below states the **current approach** (with file/function references), the **target agentic approach**, concrete **deliverables**, **acceptance criteria**, and a **status checkbox** so progress can be tracked end to end.

---

## Table of Contents

1. [Guiding Principles](#1-guiding-principles)
2. [Target Architecture](#2-target-architecture)
3. [Phase 0 — Foundations](#phase-0--foundations-no-behavior-change)
4. [Phase 1 — Analyst Agent (Reasoning)](#phase-1--analyst-agent-reasoning)
5. [Phase 2 — Detection Agent](#phase-2--detection-agent)
6. [Phase 3 — Recon & Data Agent](#phase-3--recon--data-agent)
7. [Phase 4 — Hypothesis Agent](#phase-4--hypothesis-agent)
8. [Phase 5 — Report Agent](#phase-5--report-agent)
9. [Phase 6 — Supervisor Agent & Dynamic Routing](#phase-6--supervisor-agent--dynamic-routing)
10. [Phase 7 — Human-in-the-Loop Checkpointing](#phase-7--human-in-the-loop-checkpointing)
11. [Phase 8 — Parallel Multi-Hunt Swarm](#phase-8--parallel-multi-hunt-swarm)
12. [Phase 9 — Enterprise Scaling](#phase-9--enterprise-scaling)
13. [Phase 10 — Evaluation & Continuous Improvement](#phase-10--evaluation--continuous-improvement)
14. [Master Feature Tracker](#14-master-feature-tracker)
15. [Risks & Mitigations](#15-risks--mitigations)
16. [Success Metrics](#16-success-metrics)

---

## 1. Guiding Principles

- **Wrap, don't rewrite.** Every MCP tool in `services/api/server.py` stays as-is. Agents call the *same* tools through the *same* MCP server — only the calling layer changes from "one fixed call per graph node" to "an LLM reasoning loop choosing among a scoped tool set."
- **LangGraph-native.** No framework migration. Use `langgraph.prebuilt.create_react_agent`, `langgraph-supervisor`, `langgraph-swarm`, and `langchain-mcp-adapters` — all designed to sit on top of exactly the stack THOS already has (LangGraph + FastMCP).
- **Incremental, reversible, feature-flagged.** Each node converts to an agent independently, behind an env flag (e.g. `AGENTIC_REASONING=true`), so the fixed pipeline keeps working as a fallback until each agent is validated.
- **Guardrails travel with the upgrade.** Every new agent inherits the discipline already in `orchestration/main.py` — step caps, timeouts, rate limits, audit logging. Autonomy without bounds is not the goal.
- **Observability before autonomy.** No agent gets more decision-making freedom than the tracing/audit layer can currently explain.

---

## 2. Target Architecture

```
                         ┌───────────────────────┐
                         │   Supervisor agent      │
                         │  dynamic hunt planning  │
                         └───┬──────┬──────┬──────┬┘
                 ┌───────────┘      │      │      └───────────┐
                 ▼                  ▼      ▼                  ▼
        ┌────────────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐
        │ Hypothesis agent│ │Recon & data  │ │ Detection  │ │Analyst agent │
        │ HEARTH + MITRE  │ │agent: query +│ │agent: Sigma│ │ReAct reasoning│
        │                 │ │fetch         │ │+ LLM       │ │              │
        └────────┬────────┘ └──────┬───────┘ └─────┬──────┘ └──────┬───────┘
                 └──────────────────┴───────────────┴────────────────┘
                                        ▼
                         ┌───────────────────────┐
                         │   MCP tool registry     │
                         │  services/* (unchanged) │
                         └───────────────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                              ▼
                ┌─────────────────┐          ┌─────────────────────┐
                │  Report agent    │          │ Human-in-the-loop    │
                │  writes findings │          │ approval / escalation│
                └─────────────────┘          └─────────────────────┘
```

Each box in the middle row is a `create_react_agent` bound to a **scoped subset** of MCP tools (least privilege, enforced at the MCP auth/scope layer, not just convention). The Supervisor holds `HuntState`, decides routing each turn, and can fan agents out in parallel. This replaces the current fixed `add_edge` chain in `services/orchestration/graph.py` — see Phase 6.

---

## Phase 0 — Foundations (no behavior change)

Infrastructure that every later phase depends on. Ships with zero change to hunt outputs.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F0.1 | MCP↔LangChain tool bridge | `services/mcp/mcp_client.py` exposes a raw `call_tool(name, args)` function; graph nodes call it directly, no LLM tool-calling schema involved | Add `langchain-mcp-adapters` to convert the live MCP tool list (`mcp_client.list_tools()`) into LangChain `Tool` objects automatically, so any `create_react_agent` can bind to them with zero manual schema-writing | `services/mcp/mcp_client.py`, new `services/mcp/agent_tools.py`, `requirements.txt` | ☐ |
| F0.2 | Agent framework dependencies | N/A | Add `langgraph>=0.2.20` (already present — confirm version supports `create_react_agent`/checkpointing), `langgraph-supervisor`, `langgraph-swarm`, `langchain-mcp-adapters` | `requirements.txt`, `services/orchestration/requirements.txt` | ☐ |
| F0.3 | Feature flags per agent | None — pipeline is monolithic | Env vars `AGENTIC_HYPOTHESIS`, `AGENTIC_RECON`, `AGENTIC_DETECTION`, `AGENTIC_ANALYST`, `AGENTIC_REPORT`, `AGENTIC_SUPERVISOR` (default `false`); `graph.py` branches node construction on these | `services/orchestration/graph.py`, `env.example` | ☐ |
| F0.4 | Postgres checkpointing | `HuntState` lives only in-memory for the duration of one `compiled_graph.astream()` call; no pause/resume | Add LangGraph `PostgresSaver` (reuses existing `POSTGRES_DSN`) so any hunt graph can checkpoint and resume — required for Phase 7's human-approval gate | `services/orchestration/graph.py`, `db/init_db.sql` (new checkpoint tables) | ☐ |
| F0.5 | Agent-level tracing | `audit.py` logs node input/output only (`hunt_steps` table) — no visibility into an agent's intermediate tool calls or "thoughts" | Integrate LangSmith or OpenTelemetry tracing at the agent level; extend `hunt_steps` (or a new `agent_thoughts` table) to store each tool call + rationale within a single node execution | `services/observability/audit.py`, `db/init_db.sql` | ☐ |
| F0.6 | Per-agent tool scopes | MCP auth is all-or-nothing: any caller with `MCP_AUTH_TOKEN` can call any tool (`services/api/server.py`'s `StaticTokenVerifier` grants one scope, `tools:call`, to everyone) | Define per-agent scopes (e.g. `tools:hypothesis`, `tools:recon`, `tools:detection`) and tag each `@mcp.tool()` with the scopes allowed to call it; issue distinct tokens per agent | `services/api/server.py`, `env.example` | ☐ |
| F0.7 | Golden hunt eval fixtures | No evaluation harness exists — correctness is checked manually per hunt | Create 5-10 golden scenarios (known hypothesis + fixture log folder + expected findings/technique) under `tests/eval/fixtures/`, used from Phase 10 onward to score any agent change before merge | new `tests/eval/` | ☐ |

---

## Phase 1 — Analyst Agent (Reasoning)

**Why first:** highest-value conversion — this is where the platform currently does the least actual "thinking" per LLM call, and where iterative investigation (the core of what a human threat hunter does) is most obviously missing.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F1.1 | Single-shot → ReAct reasoning loop | `services/reasoning/reasoning.py`'s `reason_node()` makes **one** call to `ollama_client.generate()` with a big static prompt (hypothesis + histogram + log sample + Sigma matches + RAG context) and parses one JSON response for `findings`/`recommendations`/`need_more_logs` | Wrap as `create_react_agent(model, tools=[fetch_siem_logs, search_knowledge_base, cache_lookup, cache_store])`. The agent can inspect evidence, decide it needs a narrower follow-up query, call `fetch_siem_logs` itself mid-reasoning, and re-evaluate — instead of only setting a flag for the graph to act on later | `services/reasoning/reasoning.py`, new `services/reasoning/analyst_agent.py` | ☐ |
| F1.2 | Preserve prompt-injection defenses | `SYSTEM_PROMPT` in `reasoning.py` already instructs the model to treat all log fields as untrusted, non-instructional data | Carry the exact same system-prompt guardrail language into the agent's system prompt — do not weaken this when converting to agent form, since an agent with live tool-calling access is a *higher*-value prompt-injection target, not a lower one | `services/reasoning/analyst_agent.py` | ☐ |
| F1.3 | Bounded tool-call loop | `max_iterations` (default 3) caps the *outer* `siem_fetch → reasoning` graph loop | Add an inner cap (`ANALYST_MAX_TOOL_CALLS`, default 5) on how many tool calls the agent can make within one node execution, independent of the outer graph loop, so a single Analyst turn can't itself run away | `services/reasoning/analyst_agent.py`, `env.example` | ☐ |
| F1.4 | Structured output contract preserved | `reason_node()` returns a dict matching `HuntState` fields (`reasoning_summary`, `findings`, `recommendations`, `need_more_logs`, `follow_up_query`) | Agent's final response must still map to the exact same `HuntState` keys — use a structured-output parser/tool (e.g. a final `submit_findings` tool call) so downstream nodes (`soc_tools`, `report`) don't need to change | `services/reasoning/analyst_agent.py`, `services/orchestration/state.py` (no changes needed if contract holds) | ☐ |
| F1.5 | A/B validation against fixed pipeline | N/A | Run both `AGENTIC_ANALYST=true` and `false` against the Phase 0 golden fixtures; compare findings quality, false-negative rate, latency, and Ollama token cost before defaulting the flag on | `tests/eval/test_analyst_agent.py` | ☐ |

---

## Phase 2 — Detection Agent

**Why second:** `soc_tools.py` currently always runs all three detection layers (SigmaHQ, THOS custom, LLM indicators) concurrently regardless of hypothesis — correct for correctness, wasteful for scale. An agent can reason about which layers are worth running.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F2.1 | Always-run-all-three → reasoned layer selection | `run_soc_tools_node()` in `services/mcp/soc_tools.py` unconditionally runs `sigmahq_engine.evaluate_all`, `sigma_engine.evaluate_all`, and `derive_detection_indicators` via `asyncio.gather` on every hunt | Detection agent decides, based on `technique_id`/`tactic`/prior findings, whether all three layers are worth the cost this turn (e.g. skip LLM-indicator derivation if SigmaHQ already found high-confidence matches) — same three tools, agent decides invocation, not blind concurrency every time | `services/mcp/soc_tools.py` → new `services/detection/detection_agent.py` | ☐ |
| F2.2 | Rule-gap self-reporting | `sigma_rule_text` already notes when `sigma_rules_hq/` is empty (static string check) | Agent can proactively flag "no rule coverage for this technique" as a structured finding fed to the Analyst agent, rather than a passive text note buried in the Sigma summary | `services/detection/detection_agent.py` | ☐ |
| F2.3 | Preserve deterministic match tagging | `_merge_rule_matches`, per-record `_sigma_match`/`_sigma_rules` tagging is deterministic Python, not LLM output | Keep 100% as-is — the agent decides *which* deterministic evaluations to run, but the evaluation itself must remain non-LLM (this is explicitly called out as a strength in the existing module docstrings; do not regress it) | `services/detection/sigma_engine.py`, `sigmahq_engine.py` (unchanged) | ☐ |
| F2.4 | Concurrency-safety review | `asyncio.gather` runs sync engines via `asyncio.to_thread` | Confirm agent-driven conditional invocation still uses `to_thread` for the CPU-bound Sigma engines when selected — don't accidentally serialize them back onto the event loop during the agent conversion | `services/detection/detection_agent.py` | ☐ |

---

## Phase 3 — Recon & Data Agent

**Why third:** query generation and log fetching currently happen in strict sequence with no self-correction if the generated query returns nothing useful.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F3.1 | Fixed query-gen → fetch → self-correcting loop | `services/hunting/query_gen.py`'s `generate_query_node` calls `generate_siem_query` once; `services/siem/siem_fetch.py`'s `fetch_logs_node` calls `fetch_siem_logs` once with whatever query came back — no feedback loop if the query returns zero/irrelevant results | Recon agent binds `generate_siem_query`, `fetch_siem_logs`, `siem_field_mapping`, `list_log_source_files`. If a fetch returns few/no matches, agent can inspect `used_fallback_unfiltered`/`record_count` and regenerate a broader or differently-scoped query before handing off, instead of relying solely on the outer `need_more_logs` loop | `services/hunting/query_gen.py`, `services/siem/siem_fetch.py` → new `services/hunting/recon_agent.py` | ☐ |
| F3.2 | SIEM-type awareness | `generate_query` takes `siem_type` as a parameter but has no way to react if a query written for one SIEM's syntax doesn't fit another | Agent explicitly calls `siem_field_mapping(siem_type)` before generating, and can re-map/regenerate if the fetch result signals a schema mismatch | `services/hunting/recon_agent.py` | ☐ |
| F3.3 | Folder-mode pre-check | `list_log_source_files` exists as a tool but is only used by the chat UI (`/log_sources` endpoint) for human preview, not by the pipeline itself | Recon agent calls `list_log_source_files` first in folder mode to confirm there's material to hunt against before generating a query, and can report "no supported log files found" as an early, cheap failure instead of running a full fetch/parse cycle for nothing | `services/hunting/recon_agent.py` | ☐ |
| F3.4 | Preserve Redis caching | `siem_connector.fetch_logs` caches by `siem_type|query|limit` | No change — agent still calls the same `fetch_siem_logs` tool, cache-key logic is untouched | `services/siem/siem_connector.py` (unchanged) | ☐ |

---

## Phase 4 — Hypothesis Agent

**Why fourth:** lower urgency (hypothesis selection is already reasonably good via semantic search), but needed for full supervisor delegation and for handling ambiguous/multi-intent free-text hunts.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F4.1 | Single best-match → reasoned selection | `services/hunting/hypothesis.py`'s `select_hypothesis` takes the top-1 semantic search result (`n_results=1`) or falls back to the first item in the full list — no reasoning about fit | Hypothesis agent calls `search_hypotheses_semantic` with `n_results=3-5`, compares candidates against the hunter's free-text intent, and picks (or asks the Supervisor to confirm) the best match with a stated rationale | `services/hunting/hypothesis.py` → new `services/hunting/hypothesis_agent.py` | ☐ |
| F4.2 | Live HEARTH refresh awareness | `refresh_hearth_kb_node` runs on every hunt (rate-limited via Redis TTL) as a separate, unconditional graph node | Fold the refresh decision into the Hypothesis agent — it can check KB freshness and decide whether a refresh is worth the latency for this specific hunt, rather than it being an unconditional prior step | `services/hunting/kb_refresh.py`, `hypothesis_agent.py` | ☐ |
| F4.3 | Multi-hypothesis detection | Free-text intent that maps to multiple plausible hypotheses currently silently collapses to one | Agent detects ambiguity (multiple high-scoring semantic matches) and surfaces it to the Supervisor, which can choose to fan out multiple Hunter agents (see Phase 8) instead of guessing | `hypothesis_agent.py`, `supervisor` (Phase 6) | ☐ |

---

## Phase 5 — Report Agent

**Why last of the specialists:** lowest autonomy need — report *writing* should stay close to deterministic (it's a compliance/audit artifact), but a light agentic layer helps with quality control.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F5.1 | Direct write → self-QA pass | `services/reporting/report.py`'s `write_report()` renders the Markdown template directly from whatever `findings`/`recommendations` text the reasoning node produced, no review step | Report agent reviews the draft against a short checklist (are IOCs present if claimed, are MITRE fields non-empty, is there at least one cited `_ref` per finding) before calling `write_hunt_report`, and can call back to Analyst for clarification if a check fails — still a single deterministic write, just gated by a review step | `services/reporting/report.py` → thin wrapper `services/reporting/report_agent.py` | ☐ |
| F5.2 | Cover-style selection assistance | `cover_style` ("1" executive / "2" SOC analyst) is chosen once by the caller at hunt-request time (`HuntRequest.cover_style`) | No agentic change needed here — keep this a user/API-level choice, not an agent decision; note explicitly in code comments so a future contributor doesn't over-engineer it | `services/reporting/report.py` (no change) | ☐ |

---

## Phase 6 — Supervisor Agent & Dynamic Routing

**This is the architectural centerpiece** — where the fixed graph becomes a genuinely agentic system.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F6.1 | Fixed edges → conditional supervisor routing | `services/orchestration/graph.py`'s `build_graph()` wires every edge with `graph.add_edge(...)`; the only branch point is `route_after_reasoning` (a plain Python `if`) | Introduce a Supervisor node using `langgraph-supervisor`'s pattern: after each specialist agent returns, the Supervisor LLM decides the next agent (or parallel set of agents) to invoke, using `HuntState` + agent outputs as context. Fixed edges remain as a **fallback path** behind `AGENTIC_SUPERVISOR=false` | `services/orchestration/graph.py`, new `services/orchestration/supervisor.py` | ☐ |
| F6.2 | Parallel fan-out | Currently only `soc_tools`'s *internal* three detection layers run concurrently (`asyncio.gather`); no two *graph nodes* ever run in parallel | Supervisor can dispatch Detection agent and a `search_knowledge_base` call in parallel with Recon agent still fetching additional logs, using LangGraph's native parallel-branch support | `services/orchestration/supervisor.py` | ☐ |
| F6.3 | Confidence-based early exit | `need_more_logs` is the only signal that changes control flow; there's no "we're confident, stop early" fast path beyond just not looping | Supervisor can end a hunt early (skip further recon iterations) once Analyst + Detection agents jointly report high confidence, saving latency/cost on straightforward hunts | `services/orchestration/supervisor.py`, `services/orchestration/state.py` (add `confidence_score`) | ☐ |
| F6.4 | Escalation branch | No escalate/human-review path exists at all today — every hunt runs to `report` unconditionally | Supervisor can route to a new `escalate` node (pages/flags for human review) when confidence is low or the Analyst agent reports a prompt-injection attempt in log data (already detected per F1.2, previously only noted in the report text) | `services/orchestration/supervisor.py`, new `services/orchestration/escalation.py` | ☐ |
| F6.5 | Fixed-graph fallback retained | N/A | Keep `build_graph()`'s deterministic version fully intact and default-on until Phase 10's eval harness proves the supervisor path is equal-or-better — this is the rollback path if agentic routing underperforms | `services/orchestration/graph.py` | ☐ |

---

## Phase 7 — Human-in-the-Loop Checkpointing

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F7.1 | No pause/resume capability | A hunt runs start-to-finish in one `astream()` call; if you want a human gate, there's no way to pause and wait for input mid-graph (explicitly called out as a Phase 2+ extension point in `main.py`'s docstring today) | Using F0.4's `PostgresSaver`, add an `interrupt_before=["report"]` (or `["escalate"]`) checkpoint so a hunt can pause for analyst sign-off before the report is finalized, then resume via a new endpoint | `services/orchestration/graph.py`, `services/orchestration/main.py` | ☐ |
| F7.2 | Resume endpoint | N/A | Add `POST /hunt/{hunt_id}/continue` (the exact endpoint already named as a future extension point in `main.py`'s module docstring) accepting an analyst decision (approve/reject/redirect) and resuming the checkpointed graph | `services/orchestration/main.py` | ☐ |
| F7.3 | Chat UI approval surface | N/A | Add an approval prompt in `services/api/app.py`'s Gradio UI when a hunt reaches a paused checkpoint, showing the draft findings and an approve/reject control | `services/api/app.py` | ☐ |
| F7.4 | Audit trail for human decisions | `hunt_steps` records graph node execution only | Add `human_decisions` table capturing who approved/rejected/redirected, when, and why | `db/init_db.sql`, `services/observability/audit.py` | ☐ |

---

## Phase 8 — Parallel Multi-Hunt Swarm

**This is the actual "scale to enterprise" lever** — one hunt at a time doesn't scale to a SOC's hypothesis backlog.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F8.1 | Single-hunt-at-a-time model → Lead Hunter dispatch | `MAX_CONCURRENT_HUNTS` (default 2) caps independent `/hunt` requests, each hand-submitted by a hunter one at a time via the chat UI | Add a Lead Hunter agent (`POST /hunt/batch`) that takes a *set* of hypotheses (or "hunt everything tagged initial-access this week") and dispatches N Hunter-agent sub-graphs concurrently, respecting the existing `_HuntSlot` concurrency gate | new `services/orchestration/lead_hunter.py`, `services/orchestration/main.py` | ☐ |
| F8.2 | Result aggregation | N/A — each hunt's report is independent, no cross-hunt correlation | Lead Hunter aggregates findings across the batch (e.g. same host/user flagged by multiple hypotheses) into a single rollup summary in addition to individual reports | `services/orchestration/lead_hunter.py`, `services/reporting/report.py` (new rollup template) | ☐ |
| F8.3 | Priority queueing | `_HuntSlot`'s bounded queue (`MAX_QUEUED_HUNTS`) is FIFO with no priority concept | Add priority tiers (e.g. hypotheses tied to active incidents jump the queue ahead of routine sweeps) | `services/orchestration/main.py` | ☐ |
| F8.4 | Swarm-safe rate limiting | `HUNT_RATE_LIMIT_PER_WINDOW` is per-`hunter_name` | Confirm Lead Hunter's batch dispatch is correctly attributed (e.g. `hunter_name="lead_hunter:<batch_id>"`) so batch hunts don't starve interactive analyst hunts sharing the same Ollama/MCP capacity | `services/orchestration/lead_hunter.py` | ☐ |

---

## Phase 9 — Enterprise Scaling

Not agent behavior — the infrastructure that lets agentic behavior run at volume without falling over.

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F9.1 | Single-instance Ollama → scalable inference | `docker-compose.yml`'s single `ollama` service; effectively serializes concurrent requests on typical single-GPU hardware, which is *why* `MAX_CONCURRENT_HUNTS` currently caps at 2 | Evaluate **vLLM** or **TGI** as a drop-in replacement (both expose OpenAI-compatible APIs `ollama_client.py` can target with minor changes) for real request batching; or run multiple Ollama replicas behind a simple round-robin/least-loaded proxy | `services/reasoning/ollama_client.py`, `docker-compose.yml` | ☐ |
| F9.2 | Tiered models by task | One model (`OLLAMA_MODEL`, default `qwen2.5:7b`) serves every LLM call — routing, query gen, and deep reasoning alike | Route lightweight decisions (Supervisor routing, tool selection) to a small/fast model; reserve the largest available model (`qwen2.5:14b`+) for the Analyst agent's actual investigative reasoning | `services/reasoning/ollama_client.py`, per-agent model config | ☐ |
| F9.3 | All-or-nothing MCP auth → per-agent scopes | Completes F0.6 in production: every agent process gets its **own** `MCP_AUTH_TOKEN` with only its scoped tool permissions, not the shared token every service currently uses | `services/api/server.py`, `docker-compose.yml` (per-agent env), `env.example` | ☐ |
| F9.4 | Node-level audit → agent-level tracing in production | Completes F0.5: LangSmith/OTel tracing wired into the actual deployed stack, dashboards for tool-call volume, latency, and cost per agent | `services/observability/*`, new Grafana/LangSmith config | ☐ |
| F9.5 | Static resource limits → autoscaling | `docker-compose.yml`'s `deploy.resources.limits` are static per service | For Kubernetes/multi-host deployments, define HPA policies keyed on hunt queue depth (`_hunt_queue_depth`) and Ollama request latency | new `k8s/` manifests (out of Compose scope) | ☐ |
| F9.6 | Cost & loop guardrails at the platform level | Guardrails today are per-mechanism (`max_iterations`, `HUNT_RATE_LIMIT_PER_WINDOW`, `ANALYST_MAX_TOOL_CALLS` from F1.3) | Add a platform-wide token/cost budget per hunt (and per batch, once F8 ships) that hard-stops any agent chain exceeding it, logged to `tool_errors` the same way existing failures are | `services/observability/cache.py` (budget counters), `services/orchestration/main.py` | ☐ |

---

## Phase 10 — Evaluation & Continuous Improvement

| ID | Feature | Current approach | Target approach | Files | Status |
|---|---|---|---|---|---|
| F10.1 | Manual verification → automated golden-hunt scoring | No regression testing exists for hunt *quality* (only `tests/detection`, `tests/mcp`, `tests/siem` unit tests, per the existing CI) | Run F0.7's golden fixtures through both the fixed pipeline and each agentic phase on every PR touching an agent; score precision/recall of expected findings, technique attribution accuracy, and false-positive rate | `tests/eval/`, `.github/workflows/tests.yml` (new job) | ☐ |
| F10.2 | No feedback loop from analysts | Analyst corrections/edits to a report are not captured anywhere today | Add a lightweight feedback capture (thumbs up/down + free-text correction) in the chat UI, stored in Postgres, reviewed periodically to refine agent system prompts (not full fine-tuning initially — prompt iteration is cheaper and faster to validate) | `services/api/app.py`, `db/init_db.sql` (new `feedback` table) | ☐ |
| F10.3 | Red-team / guardrail testing | Prompt-injection defense (F1.2) exists in the system prompt but is untested against adversarial log content | Add adversarial test cases (log records containing injected instructions, role markers, "ignore previous instructions" strings) to the eval suite, confirming the Analyst agent still flags rather than obeys them | `tests/eval/test_prompt_injection.py` | ☐ |
| F10.4 | Continuous ruleset freshness | `fetch_sigmahq_rules.py` is a manual script run to re-vendor rules | Schedule it (cron/CI job) and alert on failure so `sigma_rules_hq/` doesn't silently drift stale across an agentic rollout | `.github/workflows/` (new scheduled job) | ☐ |

---

## 14. Master Feature Tracker

Flat checklist view of every feature across all phases — use this section as the single source of truth for progress.

### Phase 0 — Foundations
- [ ] F0.1 MCP↔LangChain tool bridge
- [ ] F0.2 Agent framework dependencies
- [ ] F0.3 Feature flags per agent
- [ ] F0.4 Postgres checkpointing
- [ ] F0.5 Agent-level tracing
- [ ] F0.6 Per-agent tool scopes
- [ ] F0.7 Golden hunt eval fixtures

### Phase 1 — Analyst Agent
- [ ] F1.1 Single-shot → ReAct reasoning loop
- [ ] F1.2 Preserve prompt-injection defenses
- [ ] F1.3 Bounded tool-call loop
- [ ] F1.4 Structured output contract preserved
- [ ] F1.5 A/B validation against fixed pipeline

### Phase 2 — Detection Agent
- [ ] F2.1 Always-run-all-three → reasoned layer selection
- [ ] F2.2 Rule-gap self-reporting
- [ ] F2.3 Preserve deterministic match tagging
- [ ] F2.4 Concurrency-safety review

### Phase 3 — Recon & Data Agent
- [ ] F3.1 Fixed query-gen → fetch → self-correcting loop
- [ ] F3.2 SIEM-type awareness
- [ ] F3.3 Folder-mode pre-check
- [ ] F3.4 Preserve Redis caching

### Phase 4 — Hypothesis Agent
- [ ] F4.1 Single best-match → reasoned selection
- [ ] F4.2 Live HEARTH refresh awareness
- [ ] F4.3 Multi-hypothesis detection

### Phase 5 — Report Agent
- [ ] F5.1 Direct write → self-QA pass
- [ ] F5.2 Cover-style selection assistance (no change — confirm decision)

### Phase 6 — Supervisor Agent & Dynamic Routing
- [ ] F6.1 Fixed edges → conditional supervisor routing
- [ ] F6.2 Parallel fan-out
- [ ] F6.3 Confidence-based early exit
- [ ] F6.4 Escalation branch
- [ ] F6.5 Fixed-graph fallback retained

### Phase 7 — Human-in-the-Loop Checkpointing
- [ ] F7.1 No pause/resume capability → checkpointed interrupt
- [ ] F7.2 Resume endpoint
- [ ] F7.3 Chat UI approval surface
- [ ] F7.4 Audit trail for human decisions

### Phase 8 — Parallel Multi-Hunt Swarm
- [ ] F8.1 Single-hunt-at-a-time → Lead Hunter dispatch
- [ ] F8.2 Result aggregation
- [ ] F8.3 Priority queueing
- [ ] F8.4 Swarm-safe rate limiting

### Phase 9 — Enterprise Scaling
- [ ] F9.1 Single-instance Ollama → scalable inference
- [ ] F9.2 Tiered models by task
- [ ] F9.3 All-or-nothing MCP auth → per-agent scopes
- [ ] F9.4 Node-level audit → agent-level tracing in production
- [ ] F9.5 Static resource limits → autoscaling
- [ ] F9.6 Cost & loop guardrails at the platform level

### Phase 10 — Evaluation & Continuous Improvement
- [ ] F10.1 Manual verification → automated golden-hunt scoring
- [ ] F10.2 No feedback loop from analysts → captured feedback
- [ ] F10.3 Red-team / guardrail testing
- [ ] F10.4 Continuous ruleset freshness

**Progress summary:** 0 / 39 features complete. Update this line as phases land; consider mirroring it into a project-tracker (Jira/Linear) issue per feature ID for team-level tracking, using the ID (e.g. `F1.1`) as the issue key prefix so this document and the tracker stay cross-referenceable.

---

## 15. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Agent tool-calling loops run away (cost/latency) | High | F1.3's inner tool-call cap, F9.6's platform-wide token budget, existing `max_iterations`/concurrency gate all layer together — no single point of failure |
| Autonomous routing produces worse hunts than the fixed pipeline | High | F6.5 keeps the deterministic graph as an always-available fallback; F10.1's golden-hunt scoring gates any flag flip to `true` |
| Prompt injection via log data becomes more dangerous with live tool-calling agents | High | F1.2 explicitly carries forward the existing untrusted-data system-prompt language; F10.3 adds adversarial regression tests before Analyst agent goes live |
| Single Ollama instance can't serve concurrent agents | Medium | F9.1 (vLLM/TGI or replica pool) is sequenced before Phase 8's parallel swarm work goes to production load |
| Per-agent MCP scopes misconfigured, over- or under-privileging an agent | Medium | F0.6/F9.3 — scope changes get their own test coverage confirming denied calls fail closed, not open |
| Team underestimates effort and ships agentic Supervisor before eval harness exists | Medium | Phase ordering in this document is deliberate: Phase 0 (eval fixtures) ships before Phase 6 (supervisor); don't reorder without accepting this risk explicitly |

---

## 16. Success Metrics

Track these before/after each phase using Phase 0's golden-hunt fixtures and the audit/tracing data from F0.5/F9.4:

- **Finding quality:** precision/recall of expected findings on golden fixtures (target: agentic ≥ fixed pipeline, not just "different")
- **Investigation depth:** average tool calls per Analyst-agent turn (proxy for how much iterative investigation is actually happening vs. Phase 1 single-shot baseline)
- **Latency:** end-to-end hunt duration, p50/p95, before/after each agent conversion — some regression is expected and acceptable in exchange for quality; define an explicit ceiling per phase before shipping
- **Cost:** LLM tokens consumed per hunt, tracked per agent once F9.4 tracing is live
- **Throughput (post-Phase 8):** concurrent hunts completed per hour via Lead Hunter batch dispatch vs. one-at-a-time baseline
- **Safety:** zero regressions on F10.3's adversarial prompt-injection test suite — this is a hard gate, not a target to trend toward
- **Human trust:** approval/rejection rate at Phase 7's checkpoint gate over time (a healthy trend is rejection rate declining as agent quality improves, not the gate being bypassed)

---

*This plan sequences the migration to minimize risk: foundational infrastructure first, highest-value single-agent conversion (Analyst) next, then the remaining specialists, then the architectural centerpiece (Supervisor), then human oversight, then scale-out, then hardening. Each phase is independently shippable and reversible via its feature flag. Update the Master Feature Tracker as the source of truth for where the team actually is.*
