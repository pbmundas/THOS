> ## SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `6d2ed7d3-4a73-4934-8372-2303d6ee16d9` |
> | Hypothesis ID | B001 |
> | MITRE ATT&CK | T1071.001 — Application Layer Protocol (sub-technique T1071.001) (Command and Control) |
> | Log source | wazuh |
> | Records analyzed | 14 |
> | Detection rules matched | 0 |
> | Detection-rule records | 1 |
> | Hunt started | 2026-07-28 01:40:10 +0530 (IST) |
> | Hunt completed | 2026-07-28 01:49:01 +0530 (IST) |
> | Report generated | 2026-07-28 01:49:01 +0530 (IST) |

---

# Threat Hunt Report: B001 — Application Layer Protocol (sub-technique T1071.001) (T1071.001) — Command and Control

## Hunt Summary

SOC analyst brief: The logs show no evidence of unauthorized outbound traffic on port 443 or data exfiltration. All 14 records are Wazuh-generated compliance checks for Amazon Linux 2023 CIS benchmarks (event type 'sca') or simulated MITRE T1071.001 command-and-control activities (event type 'Purple lab: web protocol command and control rehearsal'). The 'rule_match' records explicitly reference MITRE T1071.001 but are part of a controlled test environment, not actual attack indicators. Verify cited records and the verifier result before containment.

### Key Evidence Highlights
No technique-specific literal artifact was identified. Review the detection-rule results, findings, and coverage assessment below; absence of a highlight is not proof of absence.

### Validation Status
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `14`
- **Technique-specific highlights:** `0`
- **Case:** `none`

---

## Hunt Timing & Audit Trail

| Event | Local timestamp |
|---|---|
| Hunt started | 2026-07-28 01:40:10 +0530 (IST) |
| Hunt completed | 2026-07-28 01:49:01 +0530 (IST) |
| Report generated | 2026-07-28 01:49:01 +0530 (IST) |

_Timestamps include the local UTC offset and timezone. Hunt completion marks the end of the investigative agent stages immediately before report rendering._

---

## Phase 1: Planning & Hypothesis Formulation
This phase establishes the hunt's objective, intelligence grounding, and execution path.

- **Hypothesis ID:** B001
- **MITRE ATT&CK Tactic:** Command and Control
- **MITRE ATT&CK Technique:** Application Layer Protocol (sub-technique T1071.001) (T1071.001)
- **Hunt Scope & Details:** Unusual spikes in outbound network traffic over port 443 may indicate unauthorized data exfiltration. Establishing normal traffic patterns to detect deviations

### MITRE ATT&CK Coverage
- **Technique:** Application Layer Protocol (sub-technique T1071.001) (`T1071.001`)
- **Tactic:** Command and Control
- **Description:** Application Layer Protocol. Referenced by 5 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Kimsuky (DPRK) is persisting PebbleDash / AppleSeed implants on Windows hosts by creating scheduled tasks named `ChromeCheck` (elevated) or ".
- **Typical data sources:** Network Traffic, DNS Logs

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
- [x] **Adaptive Replan** (`adaptive_replan`)
- [x] **Threat Intel** (`threat_intel`)
- [x] **AI Security Reasoning** (`reasoning`)
- [x] **Verify Evidence Citations** (`verifier`)
- [x] **Draft Detection Rules** (`detection_engineering`)
- [x] **Adapt Brief Tone** (`communication`)
- [x] **Compile Hunt Report** (`report`)

---

## Phase 2: Ingestion & Normalization
This phase validates the collection, parsing, and filtering of telemetry data.

- **Telemetry Source:** wazuh
- **Ingestion Status & Diagnostics:**
- Records fetched: 13
- Total live-SIEM matches before result cap: 1560
- Records analyzed after dedup: 14


### SIEM Queries Executed
```
{"query":{"simple_query_string":{"query":"unusual spikes outbound traffic over port indicate unauthorized","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","agent.name","decoder.name","location"],"default_operator":"or"}}}
```

### Guardrail Sentinel Scan
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 14 records)

---

## Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### Detection Rule Matches
No static detection rule matched any of the 14 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `partial` — 0 covered, 2 partial, 0 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `partial` | medium | observed relevant device type(s) network, but not the required event category |
| DNS Logs | `partial` | medium | observed relevant device type(s) network, but not the required event category |

**Observed device types:** `{"network": 14}`

**Observed event categories:** `{"authentication": 14}`


**Coverage gaps and health alerts:**

- ATT&CK T1071.001 telemetry `Network Traffic` is partial: observed relevant device type(s) network, but not the required event category.
- ATT&CK T1071.001 telemetry `DNS Logs` is partial: observed relevant device type(s) network, but not the required event category.


---

## Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### Analysis Reliability
**Model reasoning completed and validated.** Mode: `model`; attempts: `1`.

### Security Findings
- [✓ hard-evidence] No evidence of unauthorized outbound traffic on port 443 or data exfiltration (evidence: All 14 records are Wazuh-generated compliance checks for Amazon Linux 2023 CIS benchmarks (event type 'sca') or simulated MITRE T1071.001 command-and-control activities (event type 'Purple lab: web protocol command and control rehearsal'); ref: 0-3,9-12)

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `8` evidence citations (`ref: N`) point to valid records in the processed logs.

### Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 8,
    "timestamp": "2026-07-27T11:40:13.404Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.404Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31158,\\\"title\\\":\\\"Ensure sudo authentication timeout is configured correctly.\\\",\\\"description\\\":\\\"sudo caches used credentials for a default of 5 minutes. This is for ease of use when …"
  },
  {
    "ref": 9,
    "timestamp": "2026-07-27T11:40:30.671Z",
    "host": "linux-victim",
    "event": "Purple lab: web protocol command and control rehearsal",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-alerts-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:30.671Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {}, \"full_log\": \"purple-lab-attack-technique=T1071.001 purple-lab-attack-run=2d74c99042ee45a7917e1d9875a4a79b\", \"id\": \"1785152430.8710933\", \"input\": {\"type\": \"log\"}, \"location\": \"/var/log/purple/auth.log\", \"manager\": {\"name\": \"wazuh.manager\"}, \"rule\": {\"description\": \"Purple lab: web protocol command and control rehearsal\", \"firedtimes\": 1, \"groups\": [\"purple_team\", \"purple_t…"
  },
  {
    "ref": 0,
    "timestamp": "2026-07-27T11:40:13.671Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.671Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31182,\\\"title\\\":\\\"Ensure password fields are not empty.\\\",\\\"description\\\":\\\"An account with an empty password field means that anybody may log in as that user without providing a passw…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-27T11:40:13.627Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.627Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31181,\\\"title\\\":\\\"Ensure accounts in /etc/passwd use shadowed passwords.\\\",\\\"description\\\":\\\"Local accounts can use shadowed passwords. With shadowed passwords, the passwords are saved…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-27T11:40:13.607Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.607Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31179,\\\"title\\\":\\\"Ensure permissions on /etc/gshadow- are configured.\\\",\\\"description\\\":\\\"The /etc/gshadow- file is used to store backup information about groups that is critical to th…"
  }
]
```

---

## Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### Audience-Tailored Brief
> SOC analyst brief: The logs show no evidence of unauthorized outbound traffic on port 443 or data exfiltration. All 14 records are Wazuh-generated compliance checks for Amazon Linux 2023 CIS benchmarks (event type 'sca') or simulated MITRE T1071.001 command-and-control activities (event type 'Purple lab: web protocol command and control rehearsal'). The 'rule_match' records explicitly reference MITRE T1071.001 but are part of a controlled test environment, not actual attack indicators. Verify cited records and the verifier result before containment.

### Actionable Recommendations
1. Verify Wazuh is configured to capture actual network traffic events (not just compliance checks) via Sysmon event IDs 1, 3, 7, 8, 10, 11, 13, 22
2. Ensure network traffic monitoring includes port 443 outbound connections by adding a filter for DestinationPort=443 in the Wazuh rule
3. Review the 'Purple lab' event type to confirm it's a test artifact and not a real C2 activity

### Proposed Detection Rule
_No rule proposal generated for this hunt._

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
  -d '{"hunt_id": "6d2ed7d3-4a73-4934-8372-2303d6ee16d9", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System). A human analyst should validate findings before action.*
