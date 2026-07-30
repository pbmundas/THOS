# THOS Hypothesis and Forensic Verification Report

**Verification date:** 2026-07-30 (Asia/Kolkata)  
**Environment:** Local Docker THOS deployment  
**Verification scope:** MCP health, hypothesis execution, hunt-report structure, and forensic regression tests

## Summary

THOS MCP and UI availability were restored by replacing placeholder application
secrets and recreating the affected services. The `thos-mcp` and `thos-chat-ui`
containers remained healthy after the fixes, and the rebuilt orchestrator successfully
authenticated to MCP and retrieved the restored governed hypothesis catalog.

The hunt-report renderer now enforces a concise investigation-only section order and
escapes dynamic values before inserting them into Markdown tables. This prevents
indicator metadata, rule titles, coverage reasons, and retrieval diagnostics from
breaking table structure.

The complete focused hypothesis, report, forensic, YARA-intake, and gateway regression
suite passed all 29 tests. A live Wazuh run of hypothesis H111 completed through the
negative evidence gate and correctly created no report. A positive H013 regression run
over the existing EVTX corpus did not reach a terminal result within the 30-minute
client window and was interrupted during deployment of the planner-schema correction;
no investigative conclusion or hunt report is claimed for that run.

## Verification Results

| Area | Result | Evidence |
|---|---|---|
| `thos-mcp` startup | Pass | Placeholder MCP token was rejected as designed; a unique secret restored startup. |
| MCP container health | Pass | Container reported `healthy` after recreation and remained healthy during authenticated tool calls. |
| Orchestrator-to-MCP authentication | Pass | Orchestrator health succeeded and `/hypotheses` returned 306 governed B/H/M entries. |
| Hypothesis catalog provenance | Pass | The 116 generated Wazuh-only `THOS-GAP-*` entries were removed; the versioned HEARTH B/H/M catalog is authoritative. |
| Technique-name search | Pass | All 306 entries expose named ATT&CK technique tags in API responses, UI search, and semantic-search documents. |
| Chat UI startup and login | Pass | The placeholder UI password was rotated, the persisted account hash was updated through the authenticated account API, and a fresh login/session cookie was verified. |
| UI upstream error handling | Pass | Slow risk analysis has a five-minute timeout; orchestrator timeouts and transport failures now return controlled HTTP 504 and 502 responses. |
| Hunt report section contract | Pass | Exact top-level order is Summary, Hypothesis and Scope, Telemetry Retrieval, Evidence and Correlation, Findings, and Recommendations. |
| Markdown table integrity | Pass | Pipes and line breaks in dynamic cells are escaped; nested metadata is rendered as deterministic JSON. |
| Negative hypothesis gate | Pass | H111 produced `not_generated_no_evidence` with zero model-reasoning attempts and no report. |
| Positive hypothesis completion | Incomplete | H013 reached the SOC/evidence-selection path over 15 parsed EVTX records but did not finish before the regression run was stopped for deployment. |
| Forensic integrity failure | Pass | Post-acquisition tampering raises the expected integrity error. |
| Forensic workflow/report | Pass | Named forensic-agent order, technical-report headings, evidence references, ATT&CK content, limitations, and legal-review text were verified. |
| Forensic tool safety | Pass | Shell-free invocation, bounded output, content routing, and non-ready catalog filtering were verified. |

## MCP Health Diagnosis and Correction

The failing container log reported:

```text
RuntimeError: MCP_AUTH_TOKEN must be explicitly configured with a unique secret of at least 24 characters
```

The configured value had the required length but contained the known `change_me`
placeholder. THOS correctly rejected it through the fail-closed secret loader. The MCP
token, orchestrator API key, and UI session secret were rotated to unique values. The
database and Redis credentials were deliberately left unchanged to avoid invalidating
persisted services outside this correction.

After recreation:

- `thos-mcp`: healthy
- MCP Streamable HTTP server: listening on the internal Docker network
- Orchestrator MCP session: negotiated successfully
- Governed hypothesis catalog: 306 canonical B/H/M entries returned

Secret values are intentionally omitted from this report.

## Hypothesis Catalog Restoration

The earlier 422-entry view combined 306 established HEARTH hypotheses with 116
generated `THOS-GAP-*` hypotheses derived from the Wazuh detection catalog. The
generated entries were the source of the vendor-specific and repetitive wording.
They have been removed from runtime merging, startup ingestion, manual refresh,
benchmarking, and the Chroma collection.

The restored catalog is:

| Family | Count |
|---|---:|
| B — Baseline / Embers | 33 |
| H — Hypothesis-driven / Flames | 247 |
| M — Model-assisted / Alchemy | 26 |
| **Total** | **306** |

Every retained entry now exposes:

- all structured ATT&CK technique IDs available on the source hypothesis;
- corresponding human-readable technique names;
- technique IDs and names in the searchable tag set;
- a `vendor-agnostic` catalog tag;
- technique names in both client-side UI search and semantic-search documents.

The few legacy entries whose structured technique field was empty are normalized
from their authored metadata or a small reviewed legacy mapping. The cross-technique
M026 alert-triage hypothesis is labeled `Cross-technique Alert Triage` rather than
being assigned an inaccurate adversary technique.

Live verification after re-ingestion:

- Chroma `hearth_kb` count: 306
- non-B/H/M IDs: 0
- hypotheses missing technique-name tags: 0
- hypotheses containing Wazuh-specific catalog content: 0
- `H013` technique-name tag: `PowerShell`

## Chat UI Health Diagnosis and Correction

The `thos-chat-ui` restart loop reported:

```text
RuntimeError: CHATUI_PASSWORD must be explicitly configured with at least 12 characters
```

The configured value contained the known `change_me` placeholder and was rejected by
the fail-closed account loader. A unique UI password was configured and the container
was recreated. Because the analyst account had already been seeded into persistent
runtime state, its older password hash was then rotated through THOS's authenticated
`/api/account/password` workflow.

Verification after rotation:

- `thos-chat-ui`: healthy
- `/health`: HTTP 200 with `{"status":"ok"}`
- fresh login: accepted for the configured analyst
- session: HTTP-only authentication cookie issued and accepted
- static application assets: served successfully on host port 7860
- risk API: slow local-model analysis receives a five-minute request budget, with
  controlled gateway responses for timeouts and connection failures

The active username and password remain stored in `.env`; password values are not
included in this report.

## Hypothesis Verification

### H111 — Network Service Discovery (T1046)

**Hunt ID:** `d20d296b-62b0-45d3-98fa-c785f6bdecbe`  
**Source:** Wazuh  
**Terminal status:** Completed  
**Report status:** `not_generated_no_evidence`  
**Reasoning mode:** `deterministic_negative_screening`  
**Model reasoning attempts:** 0  
**Report path:** None

The source-specific query generator returned an empty query, so the Wazuh source was
recorded as `query_generation_failed`. No telemetry record reached the evidence gate.
THOS therefore made no assertion that T1046 activity was absent; it recorded the source
gap and correctly prohibited model reasoning and report generation.

This result validates fail-closed behavior, not the hypothesis itself.

### H013 — PowerShell (T1059.001)

**Hunt ID:** `82becaf4-30c8-41ce-a79b-ce4592bab49d`  
**Source:** Existing local EVTX evidence under `/data/log_sources`  
**Parsed records:** 15  
**Last completed stage:** Guardrail  
**Terminal status:** Failed after controlled orchestrator replacement  
**Report path:** None

The run reached local Sigma evaluation and evidence-selection inference. The initial
planner required multiple attempts because its output schema permitted arbitrary source
labels while the deterministic validator required the exact configured source name. The
schema now constrains source priority to the live allowed-source enum, exact source count,
and unique values.

The positive run was not allowed to produce a partial or synthetic conclusion. Because
it did not complete citation verification, no hunt report was generated.

## Correct Hunt-Report Structure

New hunt reports use the following top-level order:

1. Summary
2. Hypothesis and Scope
3. Telemetry Retrieval
4. Evidence and Correlation
5. Findings
6. Recommendations

Audit trails, case workflow, feedback instructions, and model-operation details are kept
out of the investigation report. Dynamic Markdown table values are normalized as
follows:

- dictionaries and lists become stable JSON;
- literal pipes become `\|`;
- embedded line breaks become `<br>`;
- absent values become empty cells rather than Python object text.

## Regression Test Evidence

The following targeted suites were executed:

```text
tests/orchestration/test_agentic_foundations.py
tests/forensics/test_forensic_workflow.py
tests/forensics/test_forensic_tools.py
tests/api/test_report_presentation.py
tests/api/test_forensic_yara_scan.py
tests/api/test_ui_gateway_upstream.py
```

Final result:

```text
29 passed in 4.67s
```

After catalog restoration, the catalog/search tests and all preceding focused
hypothesis, report, forensic, YARA, and gateway regressions were executed together:

```text
tests/hunting/test_hypothesis_catalog.py
tests/orchestration/test_agentic_foundations.py
tests/forensics/test_forensic_workflow.py
tests/forensics/test_forensic_tools.py
tests/api/test_ui_gateway_upstream.py
tests/api/test_forensic_yara_scan.py
tests/api/test_report_presentation.py
```

Final result:

```text
36 passed in 2.35s
```

Verified forensic behaviors include:

- full-file SHA-256 and size verification against chain-of-custody metadata;
- fail-closed handling after evidence tampering;
- deterministic ordering and audit events for the named forensic agents;
- a technical report containing chain of custody, proven facts, unresolved anomalies,
  ATT&CK references, timeline, limitations, and legal/evidentiary review requirements;
- subprocess execution without a shell and with bounded output;
- content-based PE routing without executing the supplied artifact;
- exclusion of deprecated, licensed-only, unavailable, and unsupported-platform tools
  from the ready-tool catalog.

## Limitations and Follow-up

- H111 did not test Wazuh evidence retrieval because query generation failed before a
  valid query was executed. Query-model tuning or a source-specific fallback should be
  verified separately before treating H111 as operationally covered.
- H013 demonstrated that local reasoning throughput is the dominant positive-hunt
  latency on this host. The run was intentionally not represented as completed.
- The planner source enum fix is deployed and unit-tested, but a new full positive hunt
  should be scheduled with a sufficiently long asynchronous monitoring window to obtain
  an evidence-verified production hunt report.
- A broader Windows-host `tests/api` run reached 12 passing tests and one environment
  failure because the host interpreter did not provide the native `yara` module. The
  focused YARA-intake regressions passed; production forensic images include the
  required YARA runtime.
- After the restored 306-entry catalog was deployed and verified, a separate active
  Compose project rooted at `C:\Users\Prasanna\Music\THOS` began replacing the same
  fixed `thos-*` container names. That external startup was not terminated. The live
  verification results above were captured before the name collision; the source,
  images, Chroma re-ingestion, and regression results for this workspace remain valid.

## Conclusion

The original `thos-mcp` unhealthy condition and the subsequent `thos-chat-ui` restart
loop are corrected and verified. The report structure and dynamic Markdown-table
defects are corrected and covered by tests. The forensic integrity, workflow,
reporting, and tool-safety regression set passes.

THOS correctly refused to generate reports for both an evidence-negative/source-failed
hunt and an interrupted positive run. No unsupported investigative conclusion was
introduced to satisfy report generation.
