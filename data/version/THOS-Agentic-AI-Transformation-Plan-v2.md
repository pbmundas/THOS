# THOS 2.0 Agentic AI Transformation Plan
### Making Every Agent Smarter, Adding New Agents, and a Fully On-Prem Multi-Model Strategy

**Prepared for:** THOS (Threat Hunting Operating System)
**Scope:** Agent intelligence upgrades, new agent proposals, on-prem LLM/embedding model strategy, multi-model routing, fine-tuning plan, infrastructure scaling
**Date:** July 2026

> **Note on source material:** The zip you uploaded did not actually contain `THOS-Agentic-AI-Transformation-Plan.md` only the THOS codebase itself (services/orchestration, reasoning, siem, detection, hunting, knowledge, mcp, observability, reporting). Rather than guess at a plan that isn't there, this document is built directly from the real, working system: an 8-node LangGraph pipeline running on Ollama + Qwen2.5:7B, with FastAPI, ChromaDB, Postgres, Redis, and FastMCP. Everything below is grounded in what your code actually does today, with concrete file/module references.

---

## 1. Executive Summary

THOS is already a genuinely well-engineered on-prem agentic hunting platform it has real prompt-injection defenses, dual-layer Sigma detection (SigmaHQ + custom), evidence-citation discipline in its reasoning prompt, caching, rate limiting, and a bounded concurrency gate. The gap isn't "does it work" it's **intelligence depth, model specialization, and agent count**. Today, one 7B general-purpose model does *everything*: query generation, indicator derivation, and deep security reasoning, run one-shot with no self-check and no memory across hunts.

This plan proposes three parallel tracks:

1. **Make the existing 8 agents smarter** add self-critique/verification loops, adaptive retrieval, confidence calibration, and ReAct-style tool use instead of single-shot generation.
2. **Add 10 new agents** a supervisor/planner, a verifier/critic, threat-intel enrichment, detection engineering, case management, coverage-gap analysis, a dedicated guardrail model, and more turning the static pipeline into a real multi-agent system.
3. **Upgrade the model fleet** replace the single Qwen2.5:7B with a *tiered, on-prem-only* fleet (small/fast → mid reasoning → deep/escalation → coding → embeddings → guardrail), routed by task, plus a concrete on-prem fine-tuning/continuous-learning pipeline so the models keep improving from real analyst feedback.

Everything recommended stays 100% on-premises no cloud APIs, consistent with THOS's core design constraint.

---

## 2. Current-State Assessment (What THOS Actually Does Today)

### 2.1 Pipeline (from `services/orchestration/graph.py`)

```
refresh_hearth_kb → hypothesis → query_gen → siem_fetch → log_processing
  → soc_tools → reasoning → [need_more_logs? → siem_fetch (loop) : report → END]
```

| # | Node | File | What it does today |
|---|------|------|---------------------|
| 1 | `refresh_hearth_kb` | `hunting/kb_refresh.py` | Pulls latest HEARTH hunting hypotheses from GitHub, Redis-TTL gated |
| 2 | `hypothesis` | `hunting/hypothesis.py` | Picks/looks up a hypothesis; semantic search fallback; maps to MITRE technique |
| 3 | `query_gen` | `hunting/query_gen.py`, `query_generator.py` | LLM turns hypothesis → SIEM query or folder-search keywords, grounded in a SIEM field-mapping KB |
| 4 | `siem_fetch` | `siem/siem_fetch.py` | Pulls logs from the selected SIEM connector or folder |
| 5 | `log_processing` | `siem/log_processing.py` | Normalizes/parses multi-format logs |
| 6 | `soc_tools` | `mcp/soc_tools.py` | **3 detection layers**: SigmaHQ community rules (pySigma), THOS hand-tuned rules, LLM-derived indicator matcher (`detection/indicator_deriver.py`) |
| 7 | `reasoning` | `reasoning/reasoning.py` | Single LLM call → structured JSON findings with citation discipline, confidence tags, prompt-injection sanitization, KB-grounded context |
| 8 | `report` | `reporting/report.py` | Renders Markdown report (exec or analyst cover style) |

### 2.2 Real strengths already in place (build on these, don't discard them)

- **Prompt-injection defense in the reasoning prompt** (`_INJECTION_MARKERS`, `_sanitize_untrusted_text`) log content is explicitly treated as untrusted data, not instructions.
- **Evidence-citation discipline** every finding must cite a `_ref` record or the histogram; confidence is tagged `hard-evidence` vs `circumstantial`.
- **Dual-layer Sigma detection** with source-tagging (`sigmahq` vs `thos`), so LLM-only techniques aren't the sole detection signal.
- **Custom knowledge base (RAG)** analysts can upload playbooks/IR runbooks; semantically retrieved into the reasoning prompt.
- **Iterative refinement loop** `need_more_logs` / `follow_up_query` lets the reasoning node ask for another SIEM pass (bounded by `max_iterations`).
- **Caching** (`observability/cache.py`) on both query-gen and reasoning, keyed on exact prompt content.
- **Concurrency gate + rate limiter** (`orchestration/main.py`) protects the single Ollama instance from being thrashed by concurrent hunts.
- **Structured JSON-schema-constrained generation** (not just `format: "json"`) to stop the model from collapsing to near-empty objects.

### 2.3 What's actually limiting "smartness" and scale

| Limitation | Where | Why it matters |
|---|---|---|
| **One generalist 7B model for every task** | `OLLAMA_MODEL=qwen2.5:7b` used for query-gen, indicator derivation, *and* deep reasoning | A 7B model is fine for short structured extraction; it is not strong enough for nuanced multi-step security reasoning, and using it for everything wastes GPU cycles better spent on a bigger model for the hard step |
| **Single-shot reasoning, no self-check** | `reasoning.py: reason_node` | One LLM call produces the final verdict; nothing verifies it, challenges over-claiming, or checks the citation rule was actually followed |
| **Static linear DAG** | `orchestration/graph.py` | No dynamic planning every hunt runs the identical 8 steps regardless of hypothesis complexity; no fan-out/parallelism, no supervisor deciding what's actually needed |
| **No cross-hunt memory** | | Each hunt starts cold; nothing recalls that a similar hypothesis was hunted last week, or what an analyst corrected last time |
| **Hard concurrency ceiling** | `MAX_CONCURRENT_HUNTS=2` default | Directly caused by one Ollama instance serving one model this is a model-fleet problem, not just an infra knob |
| **No enrichment (IOC/threat-intel)** | | Findings aren't cross-checked against any on-prem threat-intel feed (MISP/OpenCTI) or internal blocklists |
| **No feedback/fine-tuning loop** | `audit.py` logs everything but nothing trains from it | The richest training signal in the system (real hunts + real analyst-corrected reports) is currently write-only |
| **No case management / ticketing** | | Reports are Markdown files on disk; nothing tracks investigation status, assignment, or SLA |
| **Detection rules are read-only** | `detection/sigma_rules/` | The system consumes Sigma rules but doesn't generate/propose new ones from what it just found |

---

## 3. Design Principles for the Upgrade

1. **Right-size the model to the task.** Small/fast model for structured extraction (query-gen, indicator lists); a strong mid-size reasoning model for the analyst-facing verdict; an escalation-only large model for hard/high-stakes cases; a dedicated small guard model for every untrusted-input surface.
2. **Reflection over single-shot.** Every high-stakes output (the reasoning verdict, generated detection rules, tickets) gets a second, adversarial pass from a **Verifier agent** before it's shown to a human.
3. **Supervisor over static DAG.** Replace the fixed linear pipeline with a planner node that decides, per-hunt, which agents actually need to run (e.g., skip enrichment if the hypothesis has no IOC-bearing fields; parallelize SigmaHQ evaluation with threat-intel enrichment since neither depends on the other).
4. **Memory as a first-class citizen.** Long-term memory (past hunts, analyst corrections, recurring false-positive patterns) feeds back into hypothesis selection and reasoning.
5. **Human-in-the-loop where it counts.** Autonomous is fine for read-only research (query-gen, enrichment); anything that *writes* somewhere else (a new Sigma rule going live, a ticket, an auto-escalation) gets an approval gate.
6. **On-prem, always.** No new agent or model in this plan calls an external API. Everything is Ollama/vLLM-served open-weight models on your own GPUs.
7. **Everything is measurable.** Every new agent ships with an eval set and a rollback path "smarter" is only real if it's benchmarked, not asserted.

---

## 4. Making the Existing 8 Agents Smarter

| Agent (node) | Current behavior | Concrete upgrade | Model impact |
|---|---|---|---|
| **Hypothesis Selector** | Single semantic search, top-1 result | Retrieve top-5 candidates, have the reasoning-tier model **rank + justify** the best fit against recent hunt history (avoid re-hunting something closed last week); fall back gracefully if KB is stale | Small/fast model (cheap re-rank call) |
| **Query Generator** | One LLM call → query/keywords, grounded in field-mapping KB | Add a **self-check pass**: after generating, validate the query syntactically against the target SIEM's grammar (regex/parser check) before executing; on failure, auto-retry with the error fed back (a 2-step ReAct loop instead of one-shot) | Small/fast model, +1 cheap retry call |
| **SIEM Fetch / Log Processing** | Static pull based on generated query | Add **adaptive query widening**: if `record_count` is near-zero, automatically broaden (time window, drop overly-specific filters) before falling back to "unfiltered," rather than jumping straight to the current fallback | No LLM needed deterministic logic |
| **SOC Tools (Detection)** | 3 static layers (SigmaHQ, THOS rules, LLM indicator matcher) run and merged | Add a **4th layer**: behavioral/statistical anomaly scoring (e.g., rare-event-type detection via the histogram already computed in `reasoning.py`) surfaced *before* reasoning, not just inside the prompt | No LLM statistics; optional small model to explain anomalies |
| **Reasoning (Analyst)** | One LLM call, JSON schema-constrained, citation-disciplined | **(a)** Upgrade the model itself (Section 7). **(b)** Add a **Verifier agent pass** (Section 5) that re-checks every finding against its cited `_ref` before the report is written reject/flag findings that cite a record that doesn't actually support the claim. **(c)** Add **self-consistency**: for ambiguous/high-severity hunts, sample 2-3 times at moderate temperature and reconcile disagreements rather than trusting a single generation | Mid-tier reasoning model + verifier pass |
| **Report Writer** | Renders one of two fixed cover styles | Route through a new **Communication Agent** (Section 5) that tailors tone/depth per audience (exec, SOC analyst, compliance/auditor) instead of two hardcoded templates | Small/fast model |
| **KB Refresh (HEARTH)** | Redis-TTL gated re-fetch from GitHub | Extend to also refresh from your on-prem MISP/OpenCTI feed and internal detection-gap findings (Section 5's Coverage-Gap agent), not just the public HEARTH repo | No LLM needed |
| **Indicator Deriver** | LLM asked once for event IDs/keywords per hypothesis | Cache-and-reuse per technique_id (not just per exact prompt as today) so the *same* MITRE technique across different hunts doesn't re-derive from scratch; periodically validate derived indicators against SigmaHQ ground truth to catch drift | Small/fast model, better cache hit rate |

---

## 5. New Agents to Add

| # | Agent | Purpose | Priority | Model tier (Sec. 7) |
|---|---|---|---|---|
| 1 | **Supervisor / Planner** | Decides per-hunt which agents/branches actually run; replaces the static linear graph with dynamic routing | High | Tier 1 (mid reasoning) |
| 2 | **Verifier / Critic** | Adversarially re-checks the reasoning node's findings against cited evidence before report generation; rejects or downgrades unsupported claims | High | Tier 2 (escalation-capable) |
| 3 | **Threat-Intel Enrichment** | Cross-references extracted IOCs (hashes, IPs, domains) against on-prem MISP/OpenCTI instance and internal blocklists; purely on-prem, no cloud lookups | High | No LLM needed for lookup; Tier 0 to summarize hits |
| 4 | **Detection Engineering** | Drafts a *new* Sigma rule from a confirmed finding that wasn't already covered by existing rules, queues it for analyst review, and (on approval) writes it into `services/detection/sigma_rules/` | Medium | Coding tier |
| 5 | **Case Management / Ticketing** | Tracks hunt → investigation lifecycle (open/in-progress/closed), assignment, SLA; exposes a queryable case store instead of loose Markdown files | Medium | No LLM for CRUD; Tier 0 for auto-summarizing case notes |
| 6 | **Coverage-Gap / Purple-Team** | Uses the ingestion diagnostics already computed (`files_scanned`, `used_fallback_unfiltered`, histogram) across *many* hunts over time to flag systemic blind spots ("Sysmon 10 has never appeared in 200 hunts audit policy gap?") | Medium | Tier 1 |
| 7 | **Communication Agent** | Produces exec/analyst/compliance-tailored narratives from one shared finding set (extends the existing `cover_style` concept) | Medium | Tier 0 |
| 8 | **Continuous-Learning / Feedback** | Captures analyst thumbs-up/down and corrections on findings, turns them into an SFT/DPO training set (Section 9) | High (long-term) | No LLM at capture time; drives future fine-tunes |
| 9 | **Guardrail / Prompt-Injection Sentinel** | A dedicated small classifier model that screens raw log batches and uploaded KB documents *before* they reach any other agent defense-in-depth on top of the existing regex sanitizer | High | Guard tier (Sec. 7) |
| 10 | **Scheduler / Autonomous Hunting** | Runs hypothesis sweeps on a schedule (already on your README roadmap as "Scheduled Hunts" / "Autonomous AI Hunting Agents"); the Supervisor decides priority order based on Coverage-Gap output | Medium | Tier 1, orchestrated |

### 5.1 Why the Verifier agent matters most

Right now, THOS asks one model to both generate findings *and* be the sole judge of its own evidence discipline. That's the single highest-leverage upgrade in this plan: a **second model, ideally a different model family than the generator**, re-reads each finding + its cited `_ref` record and answers one question *"does this record actually support this claim, yes/no, and is the confidence tag justified?"* Any finding that fails is either dropped, downgraded to `circumstantial`, or triggers a re-generation. This is cheap (short, focused prompts) and directly targets hallucination risk in a domain (security findings feeding real response decisions) where it matters most.

---

## 6. Multi-Agent Orchestration Redesign

Proposed LangGraph topology (extends, doesn't replace, your existing `HuntState`):

```
refresh_hearth_kb → hypothesis → SUPERVISOR (plan)
        │
        ├── query_gen → siem_fetch → log_processing ──┐
        ├── threat_intel_enrichment (parallel) ────────┤
        └── coverage_gap_check (parallel, read-only) ──┤
                                                         ▼
                                                    soc_tools
                                                         ▼
                                                    reasoning
                                                         ▼
                                                   VERIFIER (critic)
                                            ┌────────────┴────────────┐
                                     pass / auto-fix            fails badly
                                            │                          │
                                     detection_engineering      escalate to
                                     (draft new rule,           human analyst
                                      queued for approval)      (approval gate)
                                            │                          │
                                            └──────────┬───────────────┘
                                                        ▼
                                              communication_agent
                                                        ▼
                                                     report
                                                        ▼
                                              case_management (create/update)
                                                        ▼
                                              feedback_capture (async, post-hoc)
```

**State schema additions to `HuntState`:**
- `plan: List[str]` which optional branches the Supervisor selected
- `enrichment_hits: List[Dict]` IOC matches from threat-intel
- `verifier_result: Dict` per-finding pass/fail + rationale
- `proposed_detection_rule: Optional[str]`
- `case_id: Optional[str]`
- `human_approval_required: bool`, `human_approval_status: Optional[str]`

**Mechanics to reuse from what you already built:** LangGraph's `add_conditional_edges` (already used for the `need_more_logs` loop) is the same mechanism for the Verifier's pass/fail branch and the human-approval gate. Your existing streaming (`/hunt/stream`) and audit logging (`audit.log_hunt_step`) extend to the new nodes with no architectural change just more node names flowing through the same NDJSON stream.

**Human-approval gate:** implement as LangGraph checkpointing (persist state to Postgres, pause, resume via a new `/hunt/{hunt_id}/continue` endpoint) this is explicitly called out as a Phase-2+ extension point in your existing `main.py` docstring, so it's a natural next step, not a new pattern.

---

## 7. On-Prem Model Recommendations (Fully Self-Hosted, No Cloud APIs)

Your instinct to move off a single Qwen2.5:7B is correct a security-reasoning agent fleet benefits from **specialization**, not one generalist model. Below is a tiered fleet, all open-weight and self-hostable on Ollama or vLLM.

### 7.1 Recommended tiers

| Tier | Role in THOS | Recommended model(s) | License | Approx. size / hardware |
|---|---|---|---|---|
| **Tier 0 Fast/structured** | Query-gen, indicator-derivation, communication-agent rewrites, case-note summarization | **Qwen3-8B**, or **Phi-4-mini-instruct** (3.8B) for the lightest deployments | Apache-2.0 / MIT | Single consumer GPU (8–16GB) or even CPU-only for Phi-4-mini |
| **Tier 1 Primary reasoning (replaces Qwen2.5:7B)** | Reasoning node, Supervisor/planner, Coverage-Gap analysis | **Qwen3.6-35B-A3B** (MoE, 3B active strong reasoning at low active-param cost) or **Qwen3-32B** (dense) | Apache-2.0 | Single 24–48GB GPU (quantized Q4/Q8) |
| **Tier 2 Escalation / Verifier / hard cases** | Verifier-Critic agent, low-confidence re-analysis, complex multi-technique hunts | **DeepSeek-R1** (or a **32B/70B distill** for lighter hardware) or **GLM-5** | MIT | Distill: single 48GB GPU; full R1/GLM-5: multi-GPU server |
| **Coding tier** | Detection Engineering agent (Sigma/YARA drafting) | **Qwen3-Coder** (480B-A35B for max quality, or a smaller Qwen-Coder variant for practicality) | Apache-2.0 | 35B active needs a dedicated GPU node for the full model; smaller coder variants run on one GPU |
| **Guard tier** | Prompt-Injection Sentinel agent, KB-upload screening | A fine-tuned **Phi-4-mini-instruct** or **Qwen3-8B** classifier (small, fast, purpose-tuned see Section 9) | Apache-2.0/MIT | Single small GPU, high throughput needed |
| **Embeddings** | ChromaDB collections (HEARTH, MITRE, SIEM-KB, custom_kb) | **Qwen3-Embedding-8B** for best quality (≈16GB FP16 / ≈5GB at Q4), or **BGE-M3** if you want a lighter, well-proven multilingual workhorse | Apache-2.0 / MIT | 5–16GB depending on quantization |

### 7.2 Why this shape

- **Qwen3 family** (Apache-2.0) is the safest license choice across the board and has the strongest reasoning-per-active-parameter ratio among open models right now, which matters because THOS is latency-sensitive (analysts are waiting on a hunt).
- **MoE models (Qwen3.6-35B-A3B)** give you a bigger effective model without needing a bigger GPU only ~3B parameters are "active" per token, so inference cost tracks closer to a much smaller dense model.
- **DeepSeek-R1 / distills** are the strongest *reasoning-specific* open models available on-prem and are MIT-licensed (explicitly permits distillation, which matters if you fine-tune from its outputs later). Reserve it for the Verifier and hard-case escalation rather than every hunt it's slower per-token, so use it where the extra rigor pays off.
- **Qwen3-Embedding-8B** materially outperforms typical default sentence-transformer embeddings on retrieval benchmarks, which directly improves your RAG-grounded reasoning and hypothesis-matching quality likely one of the highest ROI-per-effort swaps in this plan since it's a drop-in replacement in `services/siem/clients.py`'s embedding call, not an architecture change.
- **A dedicated Guard-tier model** is worth the extra deployment because your reasoning prompt already treats log content as adversarial input a purpose-tuned classifier catches injection attempts *before* they reach any agent, rather than relying solely on the current regex list, which is defense-in-depth but not infinitely extensible against novel phrasing.

### 7.3 Serving stack

- **Ollama** remains the right choice for Tier 0/Guard (simple, GGUF-quantized, low ops overhead) keep your current `ollama_client.py` pattern, just add `OLLAMA_MODEL` per agent instead of one global env var.
- **vLLM** (or SGLang) is worth introducing for Tier 1/Tier 2/Coding, where you'll want higher throughput under concurrent hunts, continuous batching, and easier multi-GPU tensor parallelism than Ollama currently gives you. Both expose an OpenAI-compatible API, so your `httpx`-based client pattern barely changes swap the base URL and payload shape per tier.
- Run each tier as its **own container/service** with its own GPU allocation, so the Tier-2 escalation model being busy never blocks Tier-0 query-gen calls this directly removes the `MAX_CONCURRENT_HUNTS=2` bottleneck, which today exists *because* everything shares one Ollama process.

---

## 8. Multi-Model Routing (Only Where It Actually Improves Performance/Load)

You asked for this specifically "if only required" here's the concrete case for THOS:

**The problem today:** every LLM call a 3-word keyword extraction and a full security-reasoning verdict goes to the same model and the same Ollama instance, so they compete for the same GPU slot. That's the direct cause of your `MAX_CONCURRENT_HUNTS=2` ceiling.

**The fix task-based routing, not a general-purpose router:**

| Call site | Route to | Rationale |
|---|---|---|
| `query_generator.py` | Tier 0 | Short structured output, high call volume, latency-sensitive |
| `indicator_deriver.py` | Tier 0 | Same structured JSON, small output |
| `reasoning.py` (main verdict) | Tier 1 | Needs real reasoning depth |
| Verifier/Critic pass | Tier 2 | Highest-stakes step worth the extra latency |
| Detection Engineering (Sigma drafting) | Coding tier | Syntax-correctness matters more than general reasoning |
| Communication Agent rewrite | Tier 0 | Restyling already-produced content, not new analysis |
| Guardrail Sentinel | Guard tier | Needs to run on *every* log batch must be cheap and fast |

This is **static routing by call-site**, not a dynamic classifier-based router (which adds its own latency and complexity) appropriate for THOS because your call sites are well-defined by the existing node structure, so the "routing decision" is really just "which node calls which model," configured once. A dynamic difficulty-classifier router (à la commercial LLM routers) would be over-engineering here unless a future need for one general-purpose "ask anything" chat endpoint emerges outside the structured hunt pipeline.

**Load benefit:** each tier gets its own concurrency budget. Tier 0 (Ollama) can serve many concurrent query-gen calls; Tier 1/2 (vLLM, GPU-pinned) get their own semaphore, generalizing your existing `_HuntSlot` pattern from one global gate to one gate per model tier a straightforward extension of code you already have.

---

## 9. Fine-Tuning & Continuous Training Plan (On-Prem)

Your `audit.py` already logs every hunt step, tool error, and report this is a training-data flywheel sitting mostly unused. Here's how to close the loop, fully on-prem.

### 9.1 Data flywheel

1. **Capture** extend the report UI / API with a lightweight analyst feedback action: thumbs-up/down per finding, plus an optional free-text correction. Store alongside the existing `audit.log_report` call in Postgres.
2. **Curate** a periodic (weekly) job assembles `(prompt, model_output, analyst_label, correction)` tuples from:
   - Reasoning node prompts + outputs + feedback
   - Verifier agent pass/fail decisions (once built) as an additional signal
   - Detection Engineering proposed rules + analyst approve/reject
3. **Filter** discard low-signal examples (e.g., hunts with `error` set, or where feedback wasn't given); de-duplicate near-identical hypothesis/log combinations.

### 9.2 Training methods (on-prem, GPU-efficient)

| Method | Use it for | Tooling |
|---|---|---|
| **LoRA / QLoRA supervised fine-tuning** | Adapting Tier 1 (reasoning model) to THOS's exact output schema, your organization's terminology, and recurring false-positive patterns | Axolotl or LLaMA-Factory, both run entirely on-prem on a single training GPU (24–48GB is enough for LoRA on a 30B-class model) |
| **DPO (Direct Preference Optimization)** | Training from analyst thumbs-up/down pairs "this finding wording was better than that one" directly optimizes for what analysts actually prefer, without needing a full reward model | Same tooling (LLaMA-Factory/Axolotl support DPO natively) |
| **Fine-tuning the Guard-tier classifier** | Purpose-built prompt-injection/PII detector train a small model (Tier 0-sized) on a labeled set of known injection patterns + your `_INJECTION_MARKERS` regex hits as weak-supervision seed data, then human-verified | Same tooling, much cheaper (small model) |

### 9.3 Cadence & governance

- **Quarterly retrain cycle** for the Tier 1 reasoning model (or triggered early if feedback volume crosses a threshold).
- **Golden regression set** freeze ~30–50 hunts (fixed hypothesis + log sample + expected finding set, human-verified) as a standing eval harness. Any new fine-tune or model swap must match or beat the current model on this set before promotion this is your quality gate, not a vibe check.
- **Canary rollout** route a small percentage (e.g. 10%) of live hunts to the new fine-tune, compare Verifier-agent pass rates and analyst feedback for 1–2 weeks, then promote or roll back.
- **Versioning** tag every fine-tune as an Ollama Modelfile (`FROM base-model` + `ADAPTER ./lora`) or a vLLM LoRA adapter path, with the training data snapshot and eval score recorded this gives you a clean audit trail matching the same discipline your `audit.py` already applies to hunts.

---

## 10. Infrastructure & Scaling Plan

| Area | Today | Proposed |
|---|---|---|
| **Model serving** | One Ollama instance, one model, `MAX_CONCURRENT_HUNTS=2` | Per-tier services (Ollama for Tier 0/Guard, vLLM for Tier 1/2/Coding), each with its own GPU allocation and concurrency budget |
| **Concurrency control** | Single in-process `asyncio.Semaphore` per orchestrator process | Generalize to a **Redis-backed distributed semaphore** per model tier, so multiple orchestrator replicas share one accurate view of GPU capacity |
| **Orchestrator** | Single FastAPI process | Stateless, horizontally scalable LangGraph checkpointing to Postgres (needed anyway for the human-approval gate) makes any replica able to resume any in-flight hunt |
| **Vector DB** | ChromaDB (HEARTH/MITRE/SIEM-KB/custom_kb collections) | Fine as-is at current scale; if `custom_kb` grows into the tens of millions of chunks, evaluate Qdrant or pgvector (keeps you on the Postgres you already run) for better horizontal scaling not urgent today |
| **GPU sizing (starting point)** | 1 GPU (whatever runs Qwen2.5:7B today) | Minimum viable multi-tier: 1× GPU for Tier 0 + Guard (can share, both are small/fast), 1× 48GB GPU for Tier 1, 1× 48GB+ GPU for Tier 2/Coding (can be shared/time-sliced early on since these are escalation-only, lower call volume) |
| **Observability** | Structured JSON logging + Postgres audit trail | Extend with per-agent token/latency dashboards (which tier is the bottleneck), and Verifier pass/fail rate as a live quality metric |

---

## 11. Security & Governance for the Expanded Agent Fleet

- **Least-privilege MCP tools per agent** the Detection Engineering agent should only have write access to a *staging* rules directory, never directly to `services/detection/sigma_rules_hq/`; promotion to live rules requires the human-approval gate.
- **Guardrail agent runs first**, before raw log content or uploaded KB documents reach any reasoning-capable agent extends, doesn't replace, the existing `_sanitize_untrusted_text`/`_INJECTION_MARKERS` defense already in `reasoning.py`.
- **Human approval required** for: new detection rules going live, auto-created tickets above a severity threshold, and any Verifier "fails badly" escalation.
- **Full audit continuity** every new agent's calls flow through the same `audit.log_hunt_step` pattern already established, so the audit trail stays uniform rather than fragmenting per-agent.

---

## 12. Phased Roadmap

| Phase | Focus | Key deliverables |
|---|---|---|
| **Phase 1 (Foundations)** | Model fleet + quick wins | Deploy Tier 0/Tier 1 models, swap embedding model to Qwen3-Embedding-8B, add Verifier agent, generalize concurrency gate per tier |
| **Phase 2 (Orchestration)** | Supervisor + memory | Add Supervisor/Planner node, LangGraph checkpointing + human-approval gate, case-management store |
| **Phase 3 (New agents)** | Fill capability gaps | Threat-Intel Enrichment (MISP/OpenCTI on-prem), Detection Engineering, Coverage-Gap agent, Communication agent |
| **Phase 4 (Learning loop)** | Continuous improvement | Analyst feedback capture, golden regression eval harness, first LoRA/DPO fine-tune cycle |
| **Phase 5 (Scale + autonomy)** | Production hardening | Scheduler/autonomous hunting, multi-replica orchestrator, distributed semaphore, quarterly retrain cadence in steady state |

This phasing also folds in items already on your README roadmap (Sigma/YARA generation, scheduled hunts, case management, autonomous hunting agents) rather than duplicating effort.

---

## 13. Success Metrics

- **Finding precision** % of "hard-evidence" findings that survive Verifier review unchanged (track over time as a quality signal)
- **False-positive rate** analyst thumbs-down rate per hunt, trending down after each fine-tune cycle
- **Coverage-gap closure** number of systemic blind spots identified and remediated (audit-policy/GPO/Sysmon-config fixes) per quarter
- **Throughput** concurrent hunts supported (target: move well past today's `MAX_CONCURRENT_HUNTS=2` once tiered serving is live)
- **Detection rule contribution** number of Detection Engineering agent-proposed rules approved and merged into the live ruleset
- **Time-to-verdict** end-to-end hunt latency, tracked per model tier to catch regressions early

---

## Appendix A Quick-Reference Model Table

| Model | Tier | License | Best for in THOS |
|---|---|---|---|
| Qwen3-8B | Tier 0 | Apache-2.0 | Query-gen, indicator derivation |
| Phi-4-mini-instruct (3.8B) | Tier 0 / Guard | MIT | Lightest-hardware deployments, guard classifier base |
| Qwen3.6-35B-A3B | Tier 1 | Apache-2.0 | Primary reasoning (replaces Qwen2.5:7B) |
| Qwen3-32B (dense) | Tier 1 alt. | Apache-2.0 | Primary reasoning if MoE serving isn't set up yet |
| DeepSeek-R1 (or 32B/70B distill) | Tier 2 | MIT | Verifier/Critic, hard-case escalation |
| GLM-5 | Tier 2 alt. | MIT | Escalation, especially for coding-adjacent findings |
| Qwen3-Coder | Coding | Apache-2.0 | Detection Engineering (Sigma/YARA drafting) |
| Qwen3-Embedding-8B | Embeddings | Apache-2.0 | All ChromaDB collections (RAG quality upgrade) |
| BGE-M3 | Embeddings alt. | MIT | If you want a lighter/well-proven multilingual default |

## Appendix B File/Module Map for Implementation

- New agents go under `services/` following the existing pattern (`services/enrichment/`, `services/verification/`, `services/detection_engineering/`, `services/case_management/`).
- Extend `services/orchestration/state.py` (`HuntState`) with the new fields listed in Section 6.
- Extend `services/orchestration/graph.py` with the new nodes and conditional edges.
- Model tier config: extend `services/reasoning/ollama_client.py`'s pattern (`OLLAMA_MODEL` env var) into a small `services/reasoning/model_router.py` that maps agent name → (base_url, model_name) per tier, so every agent stays a one-line `generate(..., tier="tier1")` call.

---

*This plan is designed to be implemented incrementally nothing here requires a rewrite of the working pipeline. Each phase layers on top of what THOS already does well.*
