# THOS Hypothesis, Hunt, and Forensic Verification Report

**Verification date:** 2026-07-30 (Asia/Kolkata)  
**Environment:** Local Docker THOS deployment  
**Final H111 hunt ID:** `5e8c0aca-8659-4d6a-b601-2513c91eeb4a`

## Executive Summary

THOS is operational. The unhealthy `thos-mcp` condition was corrected by replacing
the rejected placeholder authentication configuration and recreating the affected
services. At final verification, MCP, Chat UI, Ollama, PostgreSQL, Redis, and Chroma
were healthy, and the recreated orchestrator returned `{"status":"ok"}`.

The governed hypothesis catalog is restored to the versioned HEARTH source: 306
established hypotheses whose identifiers begin with B-, H-, or M-. The previously
visible total of 422 was not an older authoritative catalog; it combined these 306
entries with 116 generated, Wazuh-derived `THOS-GAP-*` entries. That vendor-specific
overlay has been removed.

All 306 retained hypotheses are vendor agnostic, searchable by ATT&CK technique ID and
human-readable technique name, visible on the Hunt Board and Configuration schedule
selector, and assigned a deterministic impact severity with a score, rationale, and
reviewable risk parameters. No hypothesis ID or SIEM vendor is hardcoded into the
severity classifier.

H111 completed successfully against the selected live Wazuh source. It retrieved 181
records from 375 live matches, analyzed 146 deduplicated records, selected three
grounded evidence records, completed model reasoning on the first attempt, passed
citation verification, and generated a structured six-section report. The report
records the selected source by name because source-specific retrieval and coverage
diagnostics are required after a user chooses a source; this does not make the
hypothesis or severity policy vendor specific.

## Final Verification Matrix

| Area | Result | Evidence |
|---|---|---|
| MCP health | Pass | `thos-mcp` reported `healthy` after the final rebuild. |
| Orchestrator health | Pass | Internal `/health` returned `{"status":"ok"}`. |
| Chat UI and login | Pass | UI container healthy; fresh analyst login returned HTTP 200. |
| Catalog provenance | Pass | Exactly 306 canonical B/H/M entries; generated Wazuh gap overlay removed. |
| ATT&CK search visibility | Pass | Technique IDs and technique names are present in tags and searchable text. |
| Hunt Board tiles | Pass | All 306 tiles visible; severity counts match the live catalog. |
| Schedule selector | Pass | All 306 hypotheses visible and filterable in Configuration. |
| Hunt progress UX | Pass | Running banner appears above tiles; detail is collapsed by default and toggles with a high-contrast control. |
| Severity coverage | Pass | 306 of 306 hypotheses have severity, score, rationale, and risk parameters. |
| H111 live hunt | Pass | Completed with model reasoning, evidence-backed finding, verifier pass, and generated report. |
| Report structure | Pass | Exact top-level order: Summary; Hypothesis and Scope; Telemetry Retrieval; Evidence and Correlation; Findings; Recommendations. |
| Forensic regressions | Pass | Integrity, workflow, tool-safety, reporting, and related focused regressions passed in the completed suites. |
| No hardcoded hypothesis logic | Pass | Catalog normalization, literal boundaries, evidence fallback, severity, UI filtering, and scheduling are metadata/configuration driven. |

## Hypothesis Catalog Restoration

The mixed 422-entry presentation consisted of:

| Source | Count |
|---|---:|
| Versioned HEARTH B/H/M catalog | 306 |
| Generated Wazuh-derived `THOS-GAP-*` overlay | 116 |
| Mixed presentation | 422 |

The authoritative restored catalog contains:

| Family | Count |
|---|---:|
| B | 33 |
| H | 247 |
| M | 26 |
| **Total** | **306** |

The generated overlay and its generator were removed from the runtime catalog path.
Every retained hypothesis exposes:

- its authored B-, H-, or M-prefixed identifier;
- ATT&CK technique IDs;
- human-readable ATT&CK technique names;
- searchable technique ID/name tags;
- vendor-agnostic metadata;
- severity, score, rationale, impact domains, affected asset classes, and review
  parameters.

Catalog normalization is driven by hypothesis metadata and shared ATT&CK mappings.
It does not branch on Wazuh, Splunk, Elastic, Sentinel, or another SIEM vendor.

## Severity Policy

Severity represents the potential impact if the hypothesis is successfully hunted and
the finding is validated. It is not a claim that an incident already occurred.

The shared policy evaluates:

- ATT&CK tactic base risk;
- potential confidentiality, integrity, availability, identity, control-plane, and
  safety impact;
- likely blast radius;
- affected asset classes;
- privilege, persistence, evasion, lateral-movement, exfiltration, and destructive
  impact factors;
- analyst-review parameters retained with the result.

Live catalog distribution:

| Severity | Count |
|---|---:|
| Critical | 33 |
| High | 201 |
| Medium | 70 |
| Low | 2 |
| Unrated | 0 |

H111 is `medium`, score `55/100`, based on Discovery tactic risk and its potential
blast radius. The policy contains no hypothesis identifiers and no vendor names.

Historical saved schedule rotations still show their previously persisted membership
distribution of 48 critical, 198 high, 58 medium, and 2 low. Those user-owned schedule
selections were preserved instead of being destructively rewritten. New filtering and
catalog views use the current 33/201/70/2 distribution.

## Hunt Board and Schedule UX

The Hunt Board loads the restored 306-entry catalog and renders its tiles with
technique-name tags, tactic, severity, and risk score. Search matches both technique
IDs and names.

When a hunt is already active:

1. the “One hunt is already running.” banner is displayed before the hypothesis tiles;
2. progress detail remains collapsed by default;
3. clicking the high-contrast control expands the current stage and progress;
4. clicking again collapses the detail;
5. tiles remain visible and searchable beneath the banner.

Configuration → Hunt Schedules loads the same catalog rather than a separate
vendor-specific list.

## H111 End-to-End Verification

- **Hypothesis:** H111 — Network Service Discovery
- **ATT&CK:** Network Service Discovery (`T1046`), Discovery
- **Configured severity:** Medium (`55/100`)
- **Selected source for this run:** Wazuh
- **Hunt status:** Completed
- **Report status:** Generated
- **Reasoning mode:** Model
- **Reasoning attempts:** 1
- **Reasoning failed:** No
- **Verification failed:** No

### Retrieval and evidence

- the grounded query compiler produced 33 clauses using governed fields and values;
- 181 records were returned from 375 live matches;
- 146 records remained after normalization and deduplication;
- the bounded evidence selector received four compact records and selected three;
- selected evidence showed TCP SYN traffic from `172.20.0.4:65192` to
  `172.20.0.2` on ports 3389, 5985, and 5986;
- the full processed corpus also supported the cited SMB/445 observation;
- Network Traffic coverage was assessed as covered;
- Process Creation coverage was explicitly recorded as unavailable from the selected
  telemetry.

The resulting finding was positive but qualified: rapid service-port discovery was
observed, while scanner-process attribution was not asserted because process telemetry
was unavailable.

### Ordered audit ledger

All 18 persisted hunt steps completed with status `ok`:

| Step | Duration |
|---|---:|
| HEARTH refresh | 7 ms |
| Hypothesis | 306 ms |
| Hunt memory | 7 ms |
| Supervisor | 101.414 s |
| Query generation | 181 ms |
| SIEM fetch | 380 ms |
| Log processing | 55 ms |
| Guardrail | 138 ms |
| SOC tools/evidence selection | 35.399 s |
| Coverage assessment | 242.983 s |
| Threat intelligence | 311 ms |
| Adaptive replan | 63.580 s |
| Negative-screening gate | 65 ms |
| Final reasoning | 241.600 s |
| Verifier | 67 ms |
| Detection engineering | 3 ms |
| Communication | 4 ms |
| Report | 9 ms |

Total wall time was approximately 11 minutes 26 seconds on the local CPU-backed model
host. No retrieval retry loop was launched after the adaptive planner determined the
available source plan was complete.

## Performance and Quality Corrections

The principal latency and reliability corrections are configuration driven:

- evidence-selector model input is capped at four compact representative records;
- every fetched record is evaluated into a complete deterministic evidence
  inventory; grounded, detection-corroborated, literal-only, and detection-only
  records are counted separately and repeated records are grouped without
  dropping their references;
- model-selected evidence is a bounded qualitative sample and is never reported
  as the total evidence set;
- evidence-selector attempts and transport retries are bounded;
- a model-generation timeout and an outer stage timeout prevent indefinite stalls;
- the selector uses the configured fast local route;
- when strict model output validation fails, a generic deterministic fallback can keep
  only records containing at least two governed literals;
- governed literal matching now uses token boundaries, preventing a value such as
  `389` from matching inside `3389`;
- indicator derivation has explicit generation and outer critical-path bounds;
- final reasoning caps records, retrieval attempts, context items, and knowledge-base
  chunks while preserving cited evidence.

Observed performance improvements:

| Measure | Before | Final H111 | Change |
|---|---:|---:|---:|
| SOC tools/evidence selection | 120.905 s | 35.399 s | 70.7% faster |
| Final reasoning prompt | 8,999 tokens | 4,941 tokens | 45.1% smaller |
| Final reasoning outcome | Timed out/interrupted in diagnostic run | Completed first attempt | Pass |

The progress-stage map was corrected to match the real graph order:
Threat Intelligence → Adaptive Replan → Negative Screening → Reasoning. This prevents
the UI from labeling valid execution as the wrong stage.

## Report Structure and Evidence Presentation

Hunt reports use exactly these top-level sections:

1. Summary
2. Hypothesis and Scope
3. Telemetry Retrieval
4. Evidence and Correlation
5. Findings
6. Recommendations

The H111 report contains:

- an executive brief;
- selected key evidence;
- hypothesis, ATT&CK, and investigation scope;
- retrieval totals, executed query, and attempt ledger;
- rule matches, threat-intelligence result, coverage matrix, completeness, and
  representative records;
- citation-verified findings;
- recommendations and detection-engineering status.

A presentation defect discovered during final validation was corrected: behavioral
evidence is now displayed in “Key Evidence,” not only artifact-type evidence. The
persisted H111 report was updated from its stored selected evidence so it no longer
claims that key evidence is absent.

## Forensic and Regression Verification

Completed regression evidence from this work:

- 112 tests passed in 21.45 seconds in the broad focused regression set;
- 19 catalog, evidence-selection, indicator, and SOC-tool tests passed in 6.36
  seconds after the bounded-performance changes;
- an earlier focused forensic/report/gateway set passed 36 tests in 2.35 seconds;
- H111 supplied the final live integration test across authentication, MCP,
  orchestration, source retrieval, evidence selection, coverage, reasoning,
  verification, reporting, and database audit persistence.

Verified forensic behaviors include:

- full-file SHA-256 and size verification against chain-of-custody metadata;
- fail-closed handling after acquired evidence is modified;
- deterministic named-agent ordering and persisted step events;
- technical reporting with chain of custody, proven facts, unresolved anomalies,
  ATT&CK context, timeline, limitations, and legal/evidentiary review requirements;
- shell-free forensic tool invocation with bounded output;
- content-based artifact routing without executing supplied evidence;
- exclusion of deprecated, unavailable, licensed-only, and unsupported-platform tools
  from the ready catalog.

The newest reasoning-cache and progress-order unit tests could not be rerun after their
last small edits because the execution approval service reported that its automatic
approval usage limit had been reached. No alternate test-execution workaround was
used. The corresponding runtime paths were nevertheless exercised by the completed
H111 run, and both rebuilt services passed their health checks. The newly added
literal-boundary and behavioral-key-evidence unit cases remain pending a fresh test
execution allowance.

## Conclusion

The unhealthy MCP condition, vendor-specific hypothesis overlay, missing hypothesis
tiles, schedule visibility, progress disclosure, severity coverage, evidence-stage
stall, progress-stage mismatch, and report evidence-presentation defect are corrected.

The final H111 hunt completed with live telemetry, grounded evidence, qualified
analysis, validated citations, a persisted 18-step audit trail, and a structured
report. The remaining measurable constraint is local model throughput, not an
unbounded execution path or an unhealthy service.
