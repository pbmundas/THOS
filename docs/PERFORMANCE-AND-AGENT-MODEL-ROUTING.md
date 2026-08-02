# THOS performance and per-agent model routing

## Result

THOS can use different locally installed Ollama models for different agents.
An administrator can open **Configuration → Agent models** to assign a model
and tier to each model-backed agent or enable resource-aware automatic
selection. The recommendation engine is advisory: it uses installed model
metadata, logical CPUs visible to the service, the configured Ollama inference
memory budget, and resident-model/VRAM telemetry. It never downloads a model or
switches an administrator's explicit override.

Set `THOS_OLLAMA_MEMORY_BUDGET_GB` to the memory that Ollama may safely consume.
The capacity assessment is not a hardware benchmark and cannot infer an
unreported GPU's total VRAM. Production model choices still require workload
tests on the actual server.

## Routing policy

The runtime configuration stores an agent's tier, optional explicit model,
context size, and output budget under `model_routing`. Explicit per-agent
settings take precedence over automatic recommendations. Scheduled-worker
environment overrides remain the final deployment-level boundary so scheduled
jobs can run on a dedicated local inference server.

Suggested intent by tier:

- `fast`, `query`, and `guard`: smallest suitable installed generation model
  for planning, extraction, query generation, and validation latency;
- `cyber` and `reasoning`: largest suitable installed model for hunt reasoning,
  coverage, forensic interpretation, investigations, and risk analysis;
- `coding`: installed coder model when available for detection engineering;
- `verifier`: conservative model/context profile where a model-backed verifier
  is configured.

Automatic selection fits model blob size within 60 percent of the configured
inference memory budget to leave room for the runtime and KV cache. An admin
must enable automatic selection; the selected assignments are persisted and
remain auditable.

## Forensic execution

The Forensic Planning Agent receives the content-derived artifact profile and
the currently installed governed tool catalog. It decides the required
capabilities, selects the tools, states the objective for each tool, and may
defer tools to a compact follow-up pass. Deterministic code validates that the
selected tools exist, cover the model-declared capabilities, and remain inside
fixed command, path, output, timeout, and plugin boundaries.

Independent SHA-256 verification, artifact lanes, selected tools, and bounded
Volatility plugins execute concurrently. Results are restored to manifest and
plan order before references are assigned, preserving repeatability. One tool
failure is isolated and retained as an evidence fact instead of cancelling the
case.

The tool catalog now includes TShark for bounded PCAP/PCAPNG examination and
SQLite for read-only integrity/schema inventory. They complement file typing,
strings, metadata, ClamAV, PE/PDF/OLE analysis, capa, FLOSS, EWF, Sleuth Kit,
RegRipper, Volatility 3, and YARA. The model—not filename-specific business
logic—decides which installed tools answer the evidentiary question; content
signatures prevent an inapplicable adapter from running.

Forensic interpretation no longer receives an arbitrary large JSON prefix. It
gets a compact evidence package that prioritizes YARA/TI facts, failures and
limitations, cited records, and a deterministic corpus-spanning record sample.
The package reports exactly how many records and facts were supplied or
omitted, so the model must state coverage limitations.

## Threat-hunt execution

Latency-sensitive Supervisor and Adaptive Replanning stages use fast routes,
bounded prompts, one model-owned refinement decision, and no hidden transport
retry loop. Coverage and final reasoning receive compact evidence samples and
explicit time/output budgets. Final reasoning retains a validated retry and
still fails closed: malformed or uncited output cannot become a report.

The zero-evidence gate remains model-free and stops unnecessary reasoning and
report work. This saves inference without changing a positive or inconclusive
investigation into a deterministic security verdict.

## Overview and risk freshness

The Overview API always aggregates persisted hunt, detection, forensic,
workflow, report, and platform data at request time. The browser loads
operational metrics and risks independently, so slow or unavailable risk
inference cannot blank the Overview page.

Risk analysis is materialized in PostgreSQL. A completed verifier-supported
hunt report or a positive persisted detection triggers a coalesced background
Risk Analysis Agent refresh. Source fingerprinting skips unchanged evidence.
The Risk page reads the latest snapshot immediately, refreshes automatically,
and continues to show the previous verified snapshot if a newer refresh fails.
Filtering by age and result limit is deterministic and never invokes the model.

## Primary tuning controls

All controls are runtime configuration values rather than investigative
conclusions embedded in code:

- `forensics.hash_concurrency`, `artifact_concurrency`, `tool_concurrency`, and
  `volatility_plugin_concurrency`;
- forensic planner/follow-up attempts, timeouts, tool caps, and compact prior
  result limits;
- forensic interpretation record/fact counts and character limits;
- coverage, supervisor, adaptive-replan, and reasoning attempts, timeouts,
  prompt limits, and output budgets;
- risk batch size, prompt size, batch concurrency, model timeout, evidence
  sample bounds, and materialized snapshot limit;
- per-agent tier, model, context, and output settings.

Raise concurrency only after measuring CPU, storage, memory, GPU, Ollama queue,
and SIEM pressure. Larger models and prompts can improve difficult analysis but
increase latency; smaller fast-tier models should be evaluated for schema
validity and stopping quality before production promotion.

## Verification

Run the complete unit/regression suite and production UI build after changing
routes or bounds. Container-image validation is also required when forensic
packages change because host-only tests mock governed command adapters and do
not prove that every binary is present in the image.
