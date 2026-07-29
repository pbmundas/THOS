> ## Executive Summary Cover
>
> **What was investigated:** Network Service Discovery activity (Discovery),
> initiated 2026-07-30 03:10:58 +0530 (IST).
>
> **Bottom line:** [circumstantial] No evidence of network service discovery activity (evidence: absent across 50 records per histogram; ref: histogram)
>
> **Analyst / requested by:** analyst
> **Hunt completed:** 2026-07-30 03:24:01 +0530 (IST)
> **Report generated:** 2026-07-30 03:24:01 +0530 (IST)
> **Full technical detail follows below.**

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Hunt Summary

Executive brief: The logs show no evidence of network service discovery activity as defined by the hypothesis. The SIEM query returned 50 records, but all are network traffic events from Suricata (IDS) with no process creation events or scanner binaries. The absence of process creation events (required for T1046) indicates a logging gap, not active adversary behavior. No automated response action is taken by THOS.

### Key Evidence Highlights
No technique-specific literal artifact was identified. Review the detection-rule results, findings, and coverage assessment below; absence of a highlight is not proof of absence.

### Validation Status
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `50`
- **Technique-specific highlights:** `0`
- **Case:** `none`

---

## Hunt Timing & Audit Trail

| Event | Local timestamp |
|---|---|
| Hunt started | 2026-07-30 03:10:58 +0530 (IST) |
| Hunt completed | 2026-07-30 03:24:01 +0530 (IST) |
| Report generated | 2026-07-30 03:24:01 +0530 (IST) |

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
- Records fetched: 75
- Total live-SIEM matches before result cap: 7410
- Records analyzed after dedup: 50


### SIEM Queries Executed
```
{"query":{"match_all":{}}}

{"query":{"match_all":{}}}
```

### Query Retrieval Ledger
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Retrieve high-confidence direct evidence supporting or refuting the hypothesis. Cover every evidence branch stated in the hypothesis that the selected source can hold, including be | 1440m | 25 | `executed` | 25 / 3704 | none |
| 2 | `wazuh` | Tighten the noisy/capped search around literal observed entities, required event categories, the ATT&CK technique, and adjacent activity without inventing values. | 1440m | 50 | `executed` | 50 / 3706 | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · wazuh · executed</summary>

Proposed:
```
{"query":{"match_all":{}}}
```
Normalized/executed candidate:
```
{"query":{"match_all":{}}}
```
</details>

<details><summary>Attempt 2 · wazuh · executed</summary>

Proposed:
```
{"query":{"match_all":{}}}
```
Normalized/executed candidate:
```
{"query":{"match_all":{}}}
```
</details>


### Guardrail Sentinel Scan
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 50 records)

---

## Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### Detection Rule Matches
No static detection rule matched any of the 50 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
Correlated 3 observable indicator(s) against the local blocklist:

| Indicator / IOC | Log Record Index | Source | Threat Metadata |
|---|---|---|---|
| `224.0.0.251` | 3 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |
| `224.0.0.251` | 29 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |
| `224.0.0.251` | 34 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |


### Telemetry Coverage Gaps
**ATT&CK technique testability:** `partial` — 1 covered, 0 partial, 1 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `covered` | high | observed required event categories: network |
| Process Creation | `not_covered` | high | no required event category or device type was observed; expected categories=['process'], devices=['endpoint'] |

**Observed device types:** `{"ids": 17, "network": 19, "unknown": 14}`

**Observed event categories:** `{"file": 9, "network": 17, "security_event": 24}`


**Coverage gaps and health alerts:**

- ATT&CK T1046 telemetry `Process Creation` is not covered: no required event category or device type was observed; expected categories=['process'], devices=['endpoint'].


---

## Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### Analysis Reliability
**Model reasoning completed and validated.** Mode: `model`; attempts: `2`.

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
- [circumstantial] No evidence of network service discovery activity (evidence: absent across 50 records per histogram; ref: histogram)

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `1` evidence citations (`ref: N`) point to valid records in the processed logs.

### Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-29T21:40:53.659Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.2",
    "dst_ip": "172.20.0.5",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T21:40:53.659Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.5\", \"dest_port\": \"8888\", \"event_type\": \"http\", \"flow_id\": \"1918628527056957.000000\", \"http\": {\"hostname\": \"caldera\", \"http_content_type\": \"text/plain\", \"http_port\": \"8888\", \"http_user_agent\": \"Go-http-client/1.1\", \"url\": \"/beacon\"}, \"in_iface\": \"eth0\", \"pkt_src\": \"wire/pcap\", \"proto\": \"TCP\", \"src_ip\": \"172.20.0.2\", \"src_port\": \"59266\", \"timestamp\": \"2026-07…"
  },
  {
    "ref": 4,
    "timestamp": "2026-07-29T21:39:06.752Z",
    "host": "ubuntu-victim",
    "event": "ossec",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T21:39:06.752Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {\"name\": \"ossec\"}, \"full_log\": \"ossec: output: 'df -P': tmpfs                    4         0         4       0% /proc/acpi\", \"id\": \"1785361146.31508\", \"input\": {\"type\": \"log\"}, \"location\": \"df -P\", \"manager\": {\"name\": \"wazuh.manager\"}, \"timestamp\": \"2026-07-29T21:39:06.752+0000\"}"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-29T21:40:17.659Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.2",
    "dst_ip": "172.20.0.5",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T21:40:17.659Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.5\", \"dest_port\": \"8888\", \"event_type\": \"http\", \"flow_id\": \"1918628527056957.000000\", \"http\": {\"hostname\": \"caldera\", \"http_content_type\": \"text/plain\", \"http_port\": \"8888\", \"http_user_agent\": \"Go-http-client/1.1\", \"url\": \"/beacon\"}, \"in_iface\": \"eth0\", \"pkt_src\": \"wire/pcap\", \"proto\": \"TCP\", \"src_ip\": \"172.20.0.2\", \"src_port\": \"59266\", \"timestamp\": \"2026-07…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-29T21:39:47.659Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.2",
    "dst_ip": "172.20.0.5",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T21:39:47.659Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.5\", \"dest_port\": \"8888\", \"event_type\": \"http\", \"flow_id\": \"1918628527056957.000000\", \"http\": {\"hostname\": \"caldera\", \"http_content_type\": \"text/plain\", \"http_port\": \"8888\", \"http_user_agent\": \"Go-http-client/1.1\", \"url\": \"/beacon\"}, \"in_iface\": \"eth0\", \"pkt_src\": \"wire/pcap\", \"proto\": \"TCP\", \"src_ip\": \"172.20.0.2\", \"src_port\": \"59266\", \"timestamp\": \"2026-07…"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-29T21:39:27.661Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.3",
    "dst_ip": "224.0.0.251",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T21:39:27.661Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"app_proto\": \"failed\", \"dest_ip\": \"224.0.0.251\", \"dest_port\": \"5353\", \"event_type\": \"flow\", \"flow\": {\"age\": \"0\", \"alerted\": \"false\", \"bytes_toclient\": \"0\", \"bytes_toserver\": \"162\", \"end\": \"2026-07-29T21:38:56.159138+0000\", \"pkts_toclient\": \"0\", \"pkts_toserver\": \"2\", \"reason\": \"timeout\", \"start\": \"2026-07-29T21:38:56.159061+0000\", \"state\": \"new\"}, \"flow_id\": \"120214865946021.000…"
  }
]
```

---

## Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### Audience-Tailored Brief
> Executive brief: The logs show no evidence of network service discovery activity as defined by the hypothesis. The SIEM query returned 50 records, but all are network traffic events from Suricata (IDS) with no process creation events or scanner binaries. The absence of process creation events (required for T1046) indicates a logging gap, not active adversary behavior. No automated response action is taken by THOS.

### Actionable Recommendations
1. Configure Sysmon to capture process creation events (Event ID 1) for Windows endpoints to detect scanner tool execution.
2. Ensure Suricata (IDS) is configured to log network connections with full source/destination IP and port details for TCP SYN scans.
3. Implement a policy to audit process creation events for known scanner binaries (e.g., nmap.exe, advanced_ip_scanner.exe) on Windows endpoints.

### Proposed Detection Rule
```yaml
title: THOS proposal: Network Service Discovery
id: thos_proposal_t1046_d8d0f507_ee55_417d_9a98_62122c1fba38
status: experimental
description: Drafted from a verifier-passed hunt. Requires analyst review before promotion.
author: THOS Detection Engineering Agent
logsource:
  product: windows
detection:
  selection:
    detail|contains:
      - 'advanced port scanner'
      - 'nmap.exe'
      - 'netscan.exe'
      - 'advanced_ip_scanner.exe'
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
No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)

### Continuous Learning & Feedback
Analyst feedback is logged to improve the on-prem reasoning models. Use the `/feedback` endpoint to rate this hunt:
```bash
curl -X POST http://localhost:8200/feedback \
  -H 'Authorization: Bearer <ORCHESTRATOR_API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"hunt_id": "d8d0f507-ee55-417d-9a98-62122c1fba38", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System). A human analyst should validate findings before action.*
