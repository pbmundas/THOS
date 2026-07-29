# THOS Enterprise-Path Regression Report

Date: 2026-07-28  
Environment: Dell Precision 3571, Intel Core i9-12900H (14 cores/20 threads), 31.69 GB RAM, NVIDIA T600 4 GB  
Test integrity: live indexed Wazuh telemetry and real managed evidence files; no generated events were used

## Executive summary

THOS completed the enterprise-path regression, but the current lab is not yet an enterprise-scale deployment. The test exercised production connectors, query generation, scheduling, negative evidence gating, model orchestration, detection-rule searches, file scanning, reporting controls, and service recovery against 86,290 real indexed documents and 102.08 MiB of real evidence files.

The most important result was a reproducible Wazuh Indexer failure. An eight-rule search drove the 1 GB Java heap into repeated `OutOfMemoryError: Java heap space` failures and caused three restarts. THOS was also retrying the failed workload, increasing pressure. The deployed fix now measures indexer heap/search pressure, serializes work above the soft limit, defers at the hard limit, caps exact hit counting, and does not retry resource-failure batches. The indexer remained running for more than 50 minutes after the last restart, with no further out-of-memory event during the post-fix workload. This is short-term regression evidence, not a substitute for a longer soak test.

The no-evidence path was reduced from 154.64 seconds to 9.10 seconds. It now performs no model reasoning and creates no report when the SIEM returns zero logs or when returned records contain no explicit rule, artifact, IOC, or behavioral match. Rehearsal data is not excluded: it is accepted whenever it explicitly matches the hypothesis.

All automated regressions pass: **204 passed, 0 failed**, with four FastAPI lifecycle deprecation warnings.

## Test scope and telemetry

| Item | Measured value |
|---|---:|
| Alert and archive indices | 15 |
| Indexed documents | 86,290 |
| Index store | 70.25 MB |
| Events in last 24 hours | 4,636 |
| Events in last 7 days | 66,546 |
| Indexer data nodes | 1 |
| Shards | 69 |
| Hypotheses | 422 |
| Ready detection rules | 1,133 |
| Ready file rules | 12,698 |
| Default actionable file rules after filtering | 12,520 |
| Real evidence files scanned | 44 |
| Evidence bytes scanned | 107,040,067 bytes (102.08 MiB) |

This volume is enough to validate production behavior and reveal resource failures, but it is not proof of performance at hundreds of millions or billions of events. Artificially copying events would have produced misleading cache, compression, cardinality, and query-selectivity behavior, so the regression did not do that.

## Search performance

| Workload | Throughput | p95 latency | Result |
|---|---:|---:|---|
| Single broad search | 5.79 requests/s | 191 ms | Passed |
| Two concurrent searches | 6.57 requests/s | 309 ms | Passed |
| Four concurrent searches | 6.73 requests/s | 604 ms | Passed |

The single-query median was 173 ms and p95 was 179 ms. Throughput flattened near 6.7 requests/s. Moving from two to four concurrent searches added little throughput while nearly doubling p95 latency. The safe operating point for this host is therefore two concurrent searches.

## Detection-rule execution

| Batch | Duration | Effective rate | Errors |
|---|---:|---:|---:|
| 1 rule | 369 ms | 2.71 rules/s | 0 |
| 2 rules | 894 ms | 2.24 rules/s | 0 |
| 4 rules | 1,690 ms | 2.37 rules/s | 0 |

When the indexer heap exceeded the 60% soft threshold, THOS automatically serialized execution instead of sending the configured wider batch. At the measured 2.24–2.71 rules/s, evaluating all 1,133 ready rules takes approximately 7.0–8.4 minutes of pure search time. Allow a 10–15 minute maintenance window for scheduling, pressure checks, connector overhead, and uneven rule complexity.

Do not send all rules as one search. With the current 1 GB indexer heap:

- Use search concurrency 2.
- Use a normal maximum rule batch width of 4 only while heap is below 60%.
- Reduce batch width to 1 at or above 60% heap.
- Defer new rule searches at or above 80% heap or when the search queue is above 50.
- Do not retry a resource-pressure failure until the pressure condition clears.

## Hypothesis pipeline

### Evidence-negative live test

Hypothesis B002 (T1219, remote access software) was executed through the real Wazuh connector.

| Version | End-to-end duration | SIEM records | Model reasoning | Report |
|---|---:|---:|---:|---:|
| Before | 154,641.75 ms | 6 unrelated records | Skipped by evidence gate | Not created |
| After | 9,095.16 ms | 0 | Not invoked | Not created |

The optimized path is 94.1% faster, approximately 17 times faster. The previous delay came from an external catalog refresh, a model-generated supervisor plan that could not alter the fixed graph, an early adaptive-reasoning pass, and model query generation using generic terms. The deployed path now uses a deterministic graph plan, keeps catalog refresh outside the hunt, moves evidence screening before adaptive/model reasoning, and prioritizes literal artifacts in the query.

The remaining 7.90 seconds is mostly query generation. The next efficiency improvement should be deterministic technique/artifact query templates, invoking a model only if the deterministic query is unavailable or invalid.

### Catalog scheduling estimate

The historical mean for four completed hunts was 640.67 seconds (10.68 minutes). If all 422 hypotheses behaved like that and ran sequentially, one full catalog would take approximately 75.1 hours. A true-positive hunt may still require 7–20 minutes because evidence processing, reasoning, validation, and report generation are legitimate work. Evidence-negative hunts now take about nine seconds in the measured case, so a new p50/p95 baseline must be accumulated before replacing the conservative schedule.

Recommended hypothesis scheduling:

- Run one hypothesis at a time on this host.
- Prioritize overdue critical and high-severity hypotheses.
- Keep true-positive reasoning separate from search and file-scan maintenance windows.
- Fit each daily batch from observed p95 duration, not a fixed catalog order.
- Initially reserve a 2-hour daily window and stop admitting work when the projected p95 completion exceeds the window.
- Recalculate the batch after at least 30 completed hunts per major workload class.

## File-scan performance

| Metric | Before | After | Improvement |
|---|---:|---:|---:|
| Duration | 50.20 s | 18.53 s | 63.1% lower |
| Throughput | 0.877 files/s | 2.375 files/s | 2.71 times |
| Data throughput | 2.03 MiB/s | 5.51 MiB/s | 2.71 times |
| Files with matches | 44/44 | 6/44 | 86.4% lower |
| Match count | 273 | 30 | 89.0% lower |
| Peak orchestrator memory | about 819 MB | about 553 MB | 32.5% lower |
| Errors | 0 | 0 | No regression |

The original default bundle included 178 generic utility, cryptographic-pattern, and deprecated rules. These produced matches in almost every file and consumed resources without useful prioritization. They remain cataloged for explicit analyst use but are excluded from the default actionable bundle.

At 5.51 MiB/s, a full 1 TiB scan would take roughly 50–53 hours before storage overhead. Enterprise scheduling must scan new or changed files incrementally, use one file-scan worker on this host, and avoid rescanning an unchanged corpus.

## Nmap finding

Nmap telemetry is present. A seven-day live query returned 176 hits, with 25 records sampled in 55.91 ms. Samples at `2026-07-27T11:40:42.685Z` contain `Nmap Scripting Engine` in Wazuh `full_log`.

The current 24-hour hunt returned zero Nmap records because those events had aged outside the configured 1,440-minute lookback. Earlier omission while the records were in-window had two causes:

1. The safe Wazuh field allowlist did not include all artifact-bearing command-line, URL, and user-agent fields.
2. Broad latest-first retrieval allowed higher-volume compliance/rehearsal records to consume the result cap.

The deployed query now includes artifact-bearing fields and prioritizes literal artifacts. Increase the hunt lookback only when the investigation requires older telemetry; do not enlarge every scheduled search because that increases indexer pressure.

## Hardcoded and dummy-logic audit

Operational results, evidence counts, and capacity numbers in this report came from live telemetry or real evidence files.

The synthetic connector is now disabled by default and fails closed. THOS defaults to real folder evidence when a live connector has not been configured. Enabling generated telemetry requires the explicit `ALLOW_SYNTHETIC_TELEMETRY=1` development setting. The older benchmark's 14-record synthetic microbenchmark is also skipped by default and is labeled as non-operational evidence. The new enterprise harness never creates events and emits `synthetic_events_used: false`.

Deterministic safety logic remains intentionally hardcoded where it defines policy rather than results: query allowlists, evidence-gate requirements, pressure thresholds, bounded result limits, and fixed orchestration edges. These controls do not fabricate findings.

Remaining hardcoded deployment defaults that must be removed before an enterprise release:

- Built-in fallback API, MCP, UI, database, and Redis credentials.
- Lab Wazuh administrator credentials and disabled certificate verification.
- Single-node indexer deployment with no high availability.

THOS currently warns about fallback credentials but does not fail startup. Changing active credentials requires operator-supplied secrets and coordinated rotation, so the regression did not silently replace them.

## Resource findings

| Component | Observed state |
|---|---|
| Orchestrator | 2 CPU/2 GB limit; about 128 MB idle after deployment |
| MCP | 2 CPU/2 GB limit; about 105 MB idle |
| Ollama | 4 CPU/8 GB limit; about 4.23 GB after model load |
| Wazuh Indexer | about 1.73 GB process/container memory; 1 GB Java heap; three recorded restarts |
| Tenzir | about 1.87 GB and 14.5% CPU while otherwise idle |

The indexer is the immediate reliability bottleneck. Sixty-nine shards for about 70 MB of data creates disproportionate heap overhead. Consolidate small daily indices with rollover/index-state management and fewer primary shards. Scheduled monitoring should query alert indices; archive indices should be reserved for deeper hunts. Querying both duplicates work.

Tenzir's continuous resource use should be justified by an active pipeline or disabled when unused. It currently consumes more memory than the indexer process and sustained CPU despite not being part of the measured THOS hunt path.

## Enterprise readiness decision

Current result: **production-path functional, not yet enterprise-scale certified**.

Before an enterprise pilot:

1. Increase the indexer Java heap to at least 2 GB for this lab and benchmark 4–8 GB for the intended retention and query volume.
2. Reduce shard count and separate routine alert searches from archive hunts.
3. Rotate all default credentials, require TLS verification, and make production startup fail when known defaults remain.
4. Put scheduled model reasoning on a separate Ollama worker/GPU.
5. Add a 24-hour soak test, then a seven-day endurance test, using sanitized real enterprise telemetry with realistic cardinality and retention.
6. Record per-workload p50/p95/p99 latency, indexer heap, queue depth, error rate, and report outcome continuously.
7. Apply admission control so searches, reasoning, and file scans cannot saturate the same resource lane.

## Verification

- Automated suite: 204 passed, 0 failed, 4 deprecation warnings, 54.11 seconds.
- Post-fix live workload: more than 44 searches, seven rule executions, zero request errors.
- Cluster state during post-fix workload: green.
- Indexer after deployment: running, restart count 3, no new out-of-memory record in the final 50-minute log window.
- Chat UI, orchestrator, MCP, model service, PostgreSQL, Redis, and vector store: running; health checks passed where configured.

