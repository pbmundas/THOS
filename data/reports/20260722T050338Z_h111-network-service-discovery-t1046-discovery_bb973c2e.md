> ## 📋 Executive Summary Cover
>
> **What was investigated:** Network Service Discovery activity (Discovery),
> initiated 2026-07-22 05:03 UTC.
>
> **Bottom line:** [✓ hard-evidence] The logs indicate a potential Nmap scan via HTTP-based requests with Nmap Scripting Engine identifiers (evidence: full_log field contains 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.or…
>
> **Analyst / requested by:** analyst
> **Full technical detail follows below.**

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

---

## 🧭 Phase 1: Planning & Hypothesis Formulation
This phase establishes the hunt's objective, intelligence grounding, and execution path.

- **Hypothesis ID:** H111
- **MITRE ATT&CK Tactic:** Discovery
- **MITRE ATT&CK Technique:** Network Service Discovery (T1046)
- **Hunt Scope & Details:** An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

### 🧠 MITRE ATT&CK Coverage
- **Technique:** Network Service Discovery (`T1046`)
- **Tactic:** Discovery
- **Description:** Network Service Discovery. Referenced by 2 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are using AI-powered tools to autonomously scan network infrastructure and enumerate high-value databases by executing thousands".
- **Typical data sources:** Network Traffic, Process Creation

_Note: this technique's canonical MITRE name/tactic come from THOS's base-technique reference table; the description is grounded in this platform's own hunting-hypothesis data, not invented._

### 🧬 Prior Hunt Memory
No recent hunts targeting this technique have been recorded in the platform database.

### 📋 Hunt Execution Plan
- [x] **Sentinel Injection Screening** (`guardrail`)
- [x] **Generate SIEM Query** (`query_gen`)
- [x] **Retrieve Log Telemetry** (`siem_fetch`)
- [x] **Parse & Normalize Logs** (`log_processing`)
- [x] **Run Sigma and Indicator Matchers** (`soc_tools`)
- [x] **Enrich IOCs with Threat Intel** (`threat_intel_enrichment`)
- [x] **AI Security Reasoning** (`reasoning`)
- [x] **Verify Evidence Citations** (`verifier`)
- [x] **Compile Hunt Report** (`report`)

---

## 📥 Phase 2: Ingestion & Normalization
This phase validates the collection, parsing, and filtering of telemetry data.

- **Telemetry Source:** wazuh
- **Ingestion Status & Diagnostics:**
- Records fetched: 4
- Total live-SIEM matches before result cap: 4
- Records analyzed after dedup: 4


### 🔍 SIEM Queries Executed
```
{"query":{"simple_query_string":{"query":"port scanning advanced scanner softperfect nmap accessible 3389","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","agent.name","decoder.name","location"],"default_operator":"or"}}}
```

### 🛡️ Guardrail Sentinel Scan
✅ **Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 4 records)

---

## 🔌 Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### 🎯 Sigma Detections
No static Sigma rule matched any of the 4 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### 📡 Threat Intelligence Enrichment
✅ No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### ⚠️ Telemetry Coverage Gaps
⚠️ **Telemetry Coverage Gaps & Health Alerts Identified:**

- Only 4 normalized record(s) reached analysis; absence conclusions are low confidence.


---

## 🔎 Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### ⚙️ Analysis Reliability
✅ **Model reasoning completed and validated.** Mode: `model`; attempts: `1`.

### 📝 Security Findings
- [✓ hard-evidence] The logs indicate a potential Nmap scan via HTTP-based requests with Nmap Scripting Engine identifiers (evidence: full_log field contains 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' in all 4 records; ref: 0,1,2,3)
- [✓ hard-evidence] No evidence of port scanning tools (e.g., nmap.exe, advanced_ip_scanner.exe) was observed in the logs (evidence: absent across 4 records per histogram; ref: histogram)

### 🧐 Verifier / Critic Validation
✅ **Passed:** All cited references validated successfully. The verifier confirmed that all `5` evidence citations (`ref: N`) point to valid records in the processed logs.

### 📊 Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-22T04:38:07.703Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.2",
    "source_file": "wazuh-alerts-4.x-2026.07.22",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-22T04:38:07.703Z\", \"agent\": {\"id\": \"029\", \"ip\": \"172.20.0.6\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"GET\", \"srcip\": \"172.20.0.2\", \"url\": \"/evox/about\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.2 - - [22/Jul/2026:04:38:07 +0000] \\\"GET /evox/about HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1784695087.1397542\", \"input\": {\"type\": \"log\"}, \"location\": \"/var…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-22T04:38:07.701Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.2",
    "source_file": "wazuh-alerts-4.x-2026.07.22",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-22T04:38:07.701Z\", \"agent\": {\"id\": \"029\", \"ip\": \"172.20.0.6\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"GET\", \"srcip\": \"172.20.0.2\", \"url\": \"/HNAP1\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.2 - - [22/Jul/2026:04:38:07 +0000] \\\"GET /HNAP1 HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1784695087.1397038\", \"input\": {\"type\": \"log\"}, \"location\": \"/var/log/nginx…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-22T04:38:07.699Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.2",
    "source_file": "wazuh-alerts-4.x-2026.07.22",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-22T04:38:07.699Z\", \"agent\": {\"id\": \"029\", \"ip\": \"172.20.0.6\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"POST\", \"srcip\": \"172.20.0.2\", \"url\": \"/sdk\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.2 - - [22/Jul/2026:04:38:07 +0000] \\\"POST /sdk HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1784695087.1396535\", \"input\": {\"type\": \"log\"}, \"location\": \"/var/log/nginx/a…"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-22T04:38:07.697Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.2",
    "source_file": "wazuh-alerts-4.x-2026.07.22",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-22T04:38:07.697Z\", \"agent\": {\"id\": \"029\", \"ip\": \"172.20.0.6\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"GET\", \"srcip\": \"172.20.0.2\", \"url\": \"/nmaplowercheck1784695087\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.2 - - [22/Jul/2026:04:38:07 +0000] \\\"GET /nmaplowercheck1784695087 HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1784695087.1396012\", \"input\": {\"type…"
  }
]
```

---

## 🚀 Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### 📢 Audience-Tailored Brief
> Executive brief: The logs show 4 near-identical 404 HTTP errors from a single host (172.20.0.2) to a Linux server (linux-victim) with URLs containing Nmap Scripting Engine identifiers, indicating a potential Nmap scan. However, no actual port scanning activity (e.g., SYN packets, known scanner binaries) was observed in the logs. The event-type histogram confirms only web-accesslog events were present, suggesting the absence of network service discovery indicators. No automated response action is taken by THOS.

### 🛠️ Actionable Recommendations
1. Verify Nmap scan activity by enabling Sysmon Event ID 1 (ProcessCreate) and Security Event ID 4688 (Process Creation) for the host 172.20.0.2
2. Check for Nmap-specific network connections using Security Event ID 4624 (Logon) with LogonType 3 (Network) and Event ID 4624 with 'Nmap Scripting Engine' in the detail field
3. Review nginx access logs for patterns of rapid sequential TCP SYN connections to common service ports (3389, 445, 5985/5986, 389)

### 📐 Proposed Detection Rule
```yaml
title: THOS proposal: Network Service Discovery
id: thos_proposal_t1046_bb973c2e_bfd1_4f39_88fc_6438449271ad
status: experimental
description: Drafted from a verifier-passed hunt. Requires analyst review before promotion.
author: THOS Detection Engineering Agent
logsource:
  product: windows
detection:
  selection:
    detail|contains:
      - 'nmap.exe'
      - 'advanced ip scanner'
      - 'softperfect network scanner'
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium
```

_Proposal only; human approval is required before promotion._

---

## 🔄 Phase 6: Lifecycle Case Management & Feedback
This phase tracks the operational lifecycle of the hunt and feeds findings back into the platform.

### 🎟️ Case & Investigation Tracking
No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)

### ⚖️ Verification & Escalation Approvals
⚖️ **Pending Approval Action:**
- **Approval ID:** `9728bf49-726b-44a4-86a7-ad5f1c7f877d`
- **Status:** `Pending` / `Requires Analyst Sign-off`

_Analyst approval is required before promotion of detection rules or case closure. Actions can be decided using the `/approvals` API endpoint._

### 📈 Continuous Learning & Feedback
Analyst feedback is logged to improve the on-prem reasoning models. Use the `/feedback` endpoint to rate this hunt:
```bash
curl -X POST http://localhost:8200/feedback \
  -H 'Authorization: Bearer <ORCHESTRATOR_API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"hunt_id": "bb973c2e-bfd1-4f39-88fc-6438449271ad", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
