> ## SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `d48f9447-3fa8-4ae5-b554-7b5008ee734b` |
> | Hypothesis ID | H111 |
> | MITRE ATT&CK | T1046 — Network Service Discovery (Discovery) |
> | Log source | wazuh |
> | Records analyzed | 43 |
> | Detection rules matched | 0 |
> | Detection-rule records | 0 |
> | Hunt started | 2026-07-30 01:03:16 +0530 (IST) |
> | Hunt completed | 2026-07-30 01:23:48 +0530 (IST) |
> | Report generated | 2026-07-30 01:23:48 +0530 (IST) |

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Hunt Summary

SOC analyst brief: The available deterministic evidence does not currently support the hunting hypothesis. THOS analyzed 43 normalized records and identified 0 records requiring review. The model-independent evidence fallback completed the analysis; an analyst should review the cited evidence before action. Verify cited records and the verifier result before containment.

### Key Evidence Highlights
- **Record 38 — network service discovery:** rule: Purple lab: network service discovery rehearsal | MITRE ID: T1046 | MITRE technique: Network Service Discovery | full log: purple-lab-attack-technique=T1046 purple-lab-attack-run=2d74c99042ee45a7917e1d9875a4a79b
- **Record 39 — network service discovery:** rule: Purple lab: network service discovery rehearsal | MITRE ID: T1046 | MITRE technique: Network Service Discovery | full log: purple-lab-attack-technique=T1046 purple-lab-attack-run=53cf304314b7487b9528c4a8978e38e9
- **Record 40 — network service discovery:** rule: Purple lab: network service discovery rehearsal | MITRE ID: T1046 | MITRE technique: Network Service Discovery | full log: purple-lab-attack-technique=T1046 purple-lab-attack-run=ddc8904b591044c498be90b8820e2e9b
- **Record 41 — network service discovery:** rule: Purple lab: network service discovery rehearsal | MITRE ID: T1046 | MITRE technique: Network Service Discovery | full log: purple-lab-attack-technique=T1046 purple-lab-attack-run=7159a640b1c3464cbc8f091ac89d3411
- **Record 42 — network service discovery:** rule: Purple lab: network service discovery rehearsal | MITRE ID: T1046 | MITRE technique: Network Service Discovery | full log: purple-lab-attack-technique=T1046 purple-lab-attack-run=5ab9a37d87894352852310f5f0e3b206

### Validation Status
- **Verifier:** `passed`
- **Reasoning mode:** `deterministic_fallback`
- **Records analyzed:** `43`
- **Technique-specific highlights:** `5`
- **Case:** `b052c4fe-15b9-4549-bf16-c90561940601`

---

## Hunt Timing & Audit Trail

| Event | Local timestamp |
|---|---|
| Hunt started | 2026-07-30 01:03:16 +0530 (IST) |
| Hunt completed | 2026-07-30 01:23:48 +0530 (IST) |
| Report generated | 2026-07-30 01:23:48 +0530 (IST) |

_Timestamps include the local UTC offset and timezone. Hunt completion marks the end of the investigative agent stages immediately before report rendering._

---

## Phase 1: Planning & Hypothesis Formulation
This phase establishes the hunt's objective, intelligence grounding, and execution path.

- **Hypothesis ID:** H111
- **MITRE ATT&CK Tactic:** Discovery
- **MITRE ATT&CK Technique:** Network Service Discovery (T1046)
- **Hunt Scope & Details:** An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

### MITRE ATT&CK Coverage
- **Technique:** Network Service Discovery (`T1046`)
- **Tactic:** Discovery
- **Description:** Network Service Discovery. Referenced by 2 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are using AI-powered tools to autonomously scan network infrastructure and enumerate high-value databases by executing thousands".
- **Typical data sources:** Network Traffic, Process Creation

_Note: this technique's canonical MITRE name/tactic come from THOS's base-technique reference table; the description is grounded in this platform's own hunting-hypothesis data, not invented._

### Prior Hunt Memory
No recent hunts targeting this technique have been recorded in the platform database.

### Hunt Execution Plan
- [x] **Generate SIEM Query** (`query_gen`)
- [x] **Retrieve Log Telemetry** (`siem_fetch`)
- [x] **Parse & Normalize Logs** (`log_processing`)
- [x] **Sentinel Injection Screening** (`guardrail`)
- [x] **Run Detection and Indicator Matchers** (`soc_tools`)
- [x] **Coverage Gap** (`coverage_gap`)
- [x] **Threat Intel** (`threat_intel`)
- [x] **Adaptive Replan** (`adaptive_replan`)
- [x] **Negative Screening Gate** (`negative_screening_gate`)
- [x] **AI Security Reasoning** (`reasoning`)
- [x] **Verify Evidence Citations** (`verifier`)
- [x] **Draft Detection Rules** (`detection_engineering`)
- [x] **Adapt Brief Tone** (`communication`)
- [x] **Compile Hunt Report** (`report`)

### Investigation Contract
- **Title:** An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scann
- **Required ATT&CK data sources:** Network Traffic, Process Creation
- **Literal observables:** advanced_ip_scanner.exe, netscan.exe, nmap.exe
- **Completion criterion:** Every selected telemetry source was queried, required ATT&CK data-source coverage was assessed, query failures were recorded, and supported leads were correlated or the evidence gate stopped model reasoning.

**Required investigation steps:**
1. Validate that each required telemetry category is available in the selected source set.
2. Run a high-precision direct-evidence query using only literal hypothesis and governed ATT&CK context.
3. If the search is empty, expand the bounded time window and run a broader technique/context query.
4. If the search is noisy or capped, tighten on observed entities, event categories, and adjacent timestamps.
5. Correlate supported leads by host, user, process, network entity, and time across selected sources.
6. Conclude only after planned retrieval branches are executed or explicitly recorded as unavailable.

---

## Phase 2: Ingestion & Normalization
This phase validates the collection, parsing, and filtering of telemetry data.

- **Telemetry Source:** wazuh
- **Ingestion Status & Diagnostics:**
- Records fetched: 68
- Total live-SIEM matches before result cap: 210
- Records analyzed after dedup: 43


### SIEM Queries Executed
```
{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}

{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}
```

### Query Retrieval Ledger
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Retrieve high-confidence direct evidence supporting or refuting the hypothesis. | 1440m | 25 | `executed` | 25 / 25 | none |
| 2 | `wazuh` | Search for literal hypothesis artifacts and ATT&CK identifiers in a larger bounded window to find deterministic evidence of network service discovery | 5760m | 50 | `executed` | 38 / 185 | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · wazuh · executed</summary>

Proposed:
```
{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}
```
Normalized/executed candidate:
```
{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}
```
</details>

<details><summary>Attempt 2 · wazuh · executed</summary>

Proposed:
```
{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}
```
Normalized/executed candidate:
```
{"query":{"simple_query_string":{"query":"advanced_ip_scanner.exe netscan.exe nmap.exe port scanning advanced scanner softperfect","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","data.command^3","data.win.eventdata.commandLine^3","data.user_agent^3","data.url^2","agent.name","decoder.name","location"],"default_operator":"or"}}}
```
</details>


### Guardrail Sentinel Scan
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 43 records)

---

## Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### Detection Rule Matches
No static detection rule matched any of the 43 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `partial` — 1 covered, 1 partial, 0 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `partial` | medium | observed relevant device type(s) network, but not the required event category |
| Process Creation | `covered` | high | observed required event categories: process |

**Observed device types:** `{"network": 18, "unknown": 25}`

**Observed event categories:** `{"authentication": 13, "file": 15, "process": 15}`


**Coverage gaps and health alerts:**

- ATT&CK T1046 telemetry `Network Traffic` is partial: observed relevant device type(s) network, but not the required event category.


---

## Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### Analysis Reliability
**Deterministic evidence fallback used.** The reasoning model did not produce a valid response after 3 attempts. THOS still generated this report from detection-rule matches, normalized telemetry, coverage analysis, and verified record citations. Analyst review is recommended before action.

- **Recorded strike reasons:** `Reasoning model did not return a complete, validated response after 3 attempts. attempt 1: ReadTimeout; attempt 2: ReadTimeout; attempt 3: ReadTimeout`

### Hunt Completeness
- **Status:** `complete_with_result_caps`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["wazuh"]`
- **Queried sources:** `["wazuh"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `["wazuh"]`
- **Retrieval attempts:** `2`
- **ATT&CK coverage status:** `partial`

### Security Findings
- [circumstantial] No deterministic rule or enrichment match was found across 43 normalized records; this is not proof that the hypothesis is false. (evidence: Event histogram across all processed records: {"Purple lab: network service discovery rehearsal": 5, "sca": 38}; ref: histogram)
- [circumstantial] Telemetry coverage limitations prevent a definitive conclusion. (evidence: ATT&CK T1046 telemetry `Network Traffic` is partial: observed relevant device type(s) network, but not the required event category.; ref: histogram)

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `2` evidence citations (`ref: N`) point to valid records in the processed logs.

### Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-29T14:21:01.868Z",
    "host": "wazuh.manager",
    "event": "sca",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T14:21:01.868Z\", \"agent\": {\"id\": \"000\", \"name\": \"wazuh.manager\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":322665195,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31145,\\\"title\\\":\\\"Ensure SSH AllowTcpForwarding is disabled.\\\",\\\"description\\\":\\\"SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server, or servers to cli…"
  },
  {
    "ref": 38,
    "timestamp": "2026-07-27T11:40:28.539Z",
    "host": "ubuntu-victim",
    "event": "Purple lab: network service discovery rehearsal",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-alerts-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:28.539Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {}, \"full_log\": \"purple-lab-attack-technique=T1046 purple-lab-attack-run=2d74c99042ee45a7917e1d9875a4a79b\", \"id\": \"1785152428.8708437\", \"input\": {\"type\": \"log\"}, \"location\": \"/var/log/purple/auth.log\", \"manager\": {\"name\": \"wazuh.manager\"}, \"rule\": {\"description\": \"Purple lab: network service discovery rehearsal\", \"firedtimes\": 1, \"groups\": [\"purple_team\", \"purple_team\", \"met…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-29T14:21:01.595Z",
    "host": "wazuh.manager",
    "event": "sca",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T14:21:01.595Z\", \"agent\": {\"id\": \"000\", \"name\": \"wazuh.manager\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":322665195,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31118,\\\"title\\\":\\\"Ensure rsyslog is not configured to receive logs from a remote client.\\\",\\\"description\\\":\\\"RSyslog supports the ability to receive messages from remote hosts, thus acting as a log serve…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-29T14:21:01.138Z",
    "host": "wazuh.manager",
    "event": "sca",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T14:21:01.138Z\", \"agent\": {\"id\": \"000\", \"name\": \"wazuh.manager\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":322665195,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31073,\\\"title\\\":\\\"Ensure rpcbind is not installed or the rpcbind services are masked.\\\",\\\"description\\\":\\\"The rpcbind utility maps RPC services to the ports on which they listen. RPC processes notify rpc…"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-29T14:21:01.118Z",
    "host": "wazuh.manager",
    "event": "sca",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T14:21:01.118Z\", \"agent\": {\"id\": \"000\", \"name\": \"wazuh.manager\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":322665195,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31071,\\\"title\\\":\\\"Ensure mail transfer agent is configured for local-only mode.\\\",\\\"description\\\":\\\"Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and tran…"
  }
]
```

---

## Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### Audience-Tailored Brief
> SOC analyst brief: The available deterministic evidence does not currently support the hunting hypothesis. THOS analyzed 43 normalized records and identified 0 records requiring review. The model-independent evidence fallback completed the analysis; an analyst should review the cited evidence before action. Verify cited records and the verifier result before containment.

### Actionable Recommendations
- Review every cited record and correlate its host, user, and timestamp with adjacent telemetry.
- Validate listed coverage gaps before treating absence of evidence as a clean result.

### Proposed Detection Rule
```yaml
title: THOS proposal: Network Service Discovery
id: thos_proposal_t1046_d48f9447_3fa8_4ae5_b554_7b5008ee734b
status: experimental
description: Drafted from a verifier-passed hunt. Requires analyst review before promotion.
author: THOS Detection Engineering Agent
logsource:
  product: windows
detection:
  selection:
    detail|contains:
      - 'advanced port scanner'
      - 'softperfect network scanner'
      - 'nmap.exe'
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium
```

_Proposal only; validate and promote it through your normal detection change-control process._

---

## Phase 6: Lifecycle Case Management & Feedback
This phase tracks the operational lifecycle of the hunt and feeds findings back into the platform.

### Case & Investigation Tracking
**Active Case Created:**
- **Case ID:** `b052c4fe-15b9-4549-bf16-c90561940601`
- **Status:** `Open` / `Pending Analyst Review`
- **Priority:** Medium

_An investigation has been automatically created in the auditing database to track findings triage and resolution._

### Continuous Learning & Feedback
Analyst feedback is logged to improve the on-prem reasoning models. Use the `/feedback` endpoint to rate this hunt:
```bash
curl -X POST http://localhost:8200/feedback \
  -H 'Authorization: Bearer <ORCHESTRATOR_API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"hunt_id": "d48f9447-3fa8-4ae5-b554-7b5008ee734b", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System). A human analyst should validate findings before action.*
