> ## SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `1c574867-1a5c-43ad-b68b-6bedb1bde7d8` |
> | Hypothesis ID | B003 |
> | MITRE ATT&CK | T1547.001 — Boot or Logon Autostart Execution (sub-technique T1547.001) (Persistence) |
> | Log source | wazuh |
> | Records analyzed | 50 |
> | Detection rules matched | 0 |
> | Detection-rule records | 0 |
> | Hunt started | 2026-07-30 01:40:00 +0530 (IST) |
> | Hunt completed | 2026-07-30 01:54:08 +0530 (IST) |
> | Report generated | 2026-07-30 01:54:08 +0530 (IST) |

---

# Threat Hunt Report: B003 — Boot or Logon Autostart Execution (sub-technique T1547.001) (T1547.001) — Persistence

## Hunt Summary

SOC analyst brief: The logs show no evidence of RDP persistence via HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms registry key tampering. The hunt covered 50 records but found only network traffic and OSSEC outputs with no registry or process events matching the hypothesis. The absence of registry events confirms the telemetry gap for this technique. Verify cited records and the verifier result before containment.

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
| Hunt started | 2026-07-30 01:40:00 +0530 (IST) |
| Hunt completed | 2026-07-30 01:54:08 +0530 (IST) |
| Report generated | 2026-07-30 01:54:08 +0530 (IST) |

_Timestamps include the local UTC offset and timezone. Hunt completion marks the end of the investigative agent stages immediately before report rendering._

---

## Phase 1: Planning & Hypothesis Formulation
This phase establishes the hunt's objective, intelligence grounding, and execution path.

- **Hypothesis ID:** B003
- **MITRE ATT&CK Tactic:** Persistence
- **MITRE ATT&CK Technique:** Boot or Logon Autostart Execution (sub-technique T1547.001) (T1547.001)
- **Hunt Scope & Details:** Executables or scripts set in the rdpwd StartupPrograms registry key may indicate that an adversary has achieved persistence by setting a program to execute during an RDP login session. Establish a baseline of expected programs that are set to execute via "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms" registry key.

### MITRE ATT&CK Coverage
- **Technique:** Boot or Logon Autostart Execution (sub-technique T1547.001) (`T1547.001`)
- **Tactic:** Persistence
- **Description:** Boot or Logon Autostart Execution. Referenced by 3 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Silver Fox is persisting the ABCDoor backdoor on Windows hosts by registering both an HKCU Run key value "AppClient" and a Scheduled Task "A".
- **Typical data sources:** Windows Registry, Process Creation

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
- **Title:** Executables or scripts set in the rdpwd StartupPrograms registry key may indicate that an adversary has achieved persistence by setting a pr
- **Required ATT&CK data sources:** Windows Registry, Process Creation
- **Literal observables:** None stated literally in the hypothesis
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
- Total live-SIEM matches before result cap: 6297
- Records analyzed after dedup: 50


### SIEM Queries Executed
```
{"query":{"match_all":{}}}

{"query":{"match_all":{}}}
```

### Query Retrieval Ledger
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Retrieve high-confidence direct evidence supporting or refuting the hypothesis. Cover every evidence branch stated in the hypothesis that the selected source can hold, including be | 1440m | 25 | `executed` | 25 / 3147 | none |
| 2 | `wazuh` | Tighten the noisy/capped search around literal observed entities, required event categories, the ATT&CK technique, and adjacent activity without inventing values. | 1440m | 50 | `executed` | 50 / 3150 | none |

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
| `224.0.0.251` | 23 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |
| `224.0.0.251` | 26 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |
| `224.0.0.251` | 32 | `local_blocklist` | {'categories': ['malicious-infrastructure'], 'category': 'malicious-infrastructure', 'confidence': 'medium', 'first_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'severity': 'high', 'source_details': {'firehol-level1': {'attribution': 'FireHOL blocklist-ipsets', 'category': 'malicious-infrastructure', 'confidence': 'medium', 'last_seen_by_thos': '2026-07-29T19:30:19.113085+00:00', 'location': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'name': 'FireHOL Level 1', 'severity': 'high'}}, 'source_name': 'FireHOL Level 1', 'source_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'sources': ['firehol-level1'], 'type': 'network'} |


### Telemetry Coverage Gaps
**ATT&CK technique testability:** `not_testable` — 0 covered, 0 partial, 2 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Windows Registry | `not_covered` | high | no required event category or device type was observed; expected categories=['process', 'registry'], devices=['endpoint'] |
| Process Creation | `not_covered` | high | no required event category or device type was observed; expected categories=['process'], devices=['endpoint'] |

**Observed device types:** `{"ids": 15, "network": 21, "unknown": 14}`

**Observed event categories:** `{"file": 10, "network": 15, "security_event": 25}`


**Coverage gaps and health alerts:**

- ATT&CK T1547.001 telemetry `Windows Registry` is not covered: no required event category or device type was observed; expected categories=['process', 'registry'], devices=['endpoint'].
- ATT&CK T1547.001 telemetry `Process Creation` is not covered: no required event category or device type was observed; expected categories=['process'], devices=['endpoint'].


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
- **ATT&CK coverage status:** `not_testable`

### Security Findings
- [hard-evidence] No registry events were observed for HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms (evidence: absent across 50 records per histogram; ref: histogram)

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `1` evidence citations (`ref: N`) point to valid records in the processed logs.

### Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-29T20:09:39.592Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.2",
    "dst_ip": "172.20.0.5",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T20:09:39.592Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.5\", \"dest_port\": \"8888\", \"event_type\": \"http\", \"flow_id\": \"1918628527056957.000000\", \"http\": {\"hostname\": \"caldera\", \"http_content_type\": \"text/plain\", \"http_port\": \"8888\", \"http_user_agent\": \"Go-http-client/1.1\", \"url\": \"/beacon\"}, \"in_iface\": \"eth0\", \"pkt_src\": \"wire/pcap\", \"proto\": \"TCP\", \"src_ip\": \"172.20.0.2\", \"src_port\": \"59266\", \"timestamp\": \"2026-07…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-29T20:09:06.722Z",
    "host": "ubuntu-victim",
    "event": "ossec",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T20:09:06.722Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {\"name\": \"ossec\"}, \"full_log\": \"ossec: output: 'df -P': tmpfs                    4         0         4       0% /proc/acpi\", \"id\": \"1785355746.31508\", \"input\": {\"type\": \"log\"}, \"location\": \"df -P\", \"manager\": {\"name\": \"wazuh.manager\"}, \"timestamp\": \"2026-07-29T20:09:06.722+0000\"}"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-29T20:09:06.721Z",
    "host": "ubuntu-victim",
    "event": "ossec",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T20:09:06.721Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {\"name\": \"ossec\"}, \"full_log\": \"ossec: output: 'df -P': overlay         1055762868 134405368 867654028      14% /\", \"id\": \"1785355746.31508\", \"input\": {\"type\": \"log\"}, \"location\": \"df -P\", \"manager\": {\"name\": \"wazuh.manager\"}, \"timestamp\": \"2026-07-29T20:09:06.721+0000\"}"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-29T20:09:06.721Z",
    "host": "ubuntu-victim",
    "event": "ossec",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T20:09:06.721Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {\"name\": \"ossec\"}, \"full_log\": \"ossec: output: 'df -P': /dev/sdd        1055762868 134405368 867654028      14% /var/log\", \"id\": \"1785355746.31508\", \"input\": {\"type\": \"log\"}, \"location\": \"df -P\", \"manager\": {\"name\": \"wazuh.manager\"}, \"timestamp\": \"2026-07-29T20:09:06.721+0000\"}"
  },
  {
    "ref": 4,
    "timestamp": "2026-07-29T20:09:06.721Z",
    "host": "ubuntu-victim",
    "event": "ossec",
    "src_ip": "172.20.0.3",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T20:09:06.721Z\", \"agent\": {\"id\": \"034\", \"ip\": \"172.20.0.3\", \"name\": \"ubuntu-victim\"}, \"decoder\": {\"name\": \"ossec\"}, \"full_log\": \"ossec: output: 'df -P': tmpfs                65536         0     65536       0% /dev\", \"id\": \"1785355746.31508\", \"input\": {\"type\": \"log\"}, \"location\": \"df -P\", \"manager\": {\"name\": \"wazuh.manager\"}, \"timestamp\": \"2026-07-29T20:09:06.721+0000\"}"
  }
]
```

---

## Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### Audience-Tailored Brief
> SOC analyst brief: The logs show no evidence of RDP persistence via HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms registry key tampering. The hunt covered 50 records but found only network traffic and OSSEC outputs with no registry or process events matching the hypothesis. The absence of registry events confirms the telemetry gap for this technique. Verify cited records and the verifier result before containment.

### Actionable Recommendations
1. Enable Sysmon registry event logging for HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms
2. Configure Windows Security Event ID 7 (RegistryEvent) to capture registry key modifications
3. Implement a registry key monitoring rule for the rdpwd StartupPrograms path using SigmaHQ rules [CYBER:sigmahq_rules:0d5675be-bc88-4172-86d3-1e96a4476536:0]

### Proposed Detection Rule
```yaml
title: THOS proposal: Boot or Logon Autostart Execution (sub-technique T1547.001)
id: thos_proposal_t1547_001_1c574867_1a5c_43ad_b68b_6bedb1bde7d8
status: experimental
description: Drafted from a verifier-passed hunt. Requires analyst review before promotion.
author: THOS Detection Engineering Agent
logsource:
  product: windows
detection:
  selection:
    detail|contains:
      - 'rdp'
      - 'startupprograms'
      - 'tscon.exe'
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
  -d '{"hunt_id": "1c574867-1a5c-43ad-b68b-6bedb1bde7d8", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System). A human analyst should validate findings before action.*
