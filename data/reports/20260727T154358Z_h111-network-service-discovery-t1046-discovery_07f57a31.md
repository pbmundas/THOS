> ## 🛡️ SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `07f57a31-676d-4022-8ef7-a0d3ff5dd465` |
> | Hypothesis ID | H111 |
> | MITRE ATT&CK | T1046 — Network Service Discovery (Discovery) |
> | Log source | wazuh |
> | Records analyzed | 18 |
> | Sigma rules matched | 0 |
> | Sigma-flagged records | 1 |
> | Hunt started | 2026-07-27 21:06:26 +0530 (IST) |
> | Hunt completed | 2026-07-27 21:13:58 +0530 (IST) |
> | Report generated | 2026-07-27 21:13:58 +0530 (IST) |

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Hunt Summary

SOC analyst brief: The logs show a single record with evidence of Nmap scripting engine usage (404 error) but no process creation of known scanners or network traffic patterns matching port scanning. The hypothesis is partially supported by the Nmap scripting engine detection but lacks critical indicators like process execution of scanners or TCP SYN flows. Verify cited records and the verifier result before containment.

### Key Evidence Highlights
- **Record 0 — nmap, nmap scripting engine:** rule: Web server 400 error code. | full log: 172.20.0.5 - - [27/Jul/2026:11:40:42 +0000] "GET /nmaplowercheck1785152442 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-" | URL: /nmaplowercheck1785152442

### Validation Status
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `18`
- **Technique-specific highlights:** `1`
- **Case:** `none`

---

## Hunt Timing & Audit Trail

| Event | Local timestamp |
|---|---|
| Hunt started | 2026-07-27 21:06:26 +0530 (IST) |
| Hunt completed | 2026-07-27 21:13:58 +0530 (IST) |
| Report generated | 2026-07-27 21:13:58 +0530 (IST) |

_Timestamps include the local UTC offset and timezone. Hunt completion marks the end of the investigative agent stages immediately before report rendering._

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
- [x] **Generate SIEM Query** (`query_gen`)
- [x] **Retrieve Log Telemetry** (`siem_fetch`)
- [x] **Parse & Normalize Logs** (`log_processing`)
- [x] **Sentinel Injection Screening** (`guardrail`)
- [x] **Run Sigma and Indicator Matchers** (`soc_tools`)
- [x] **Coverage Gap** (`coverage_gap`)
- [x] **Adaptive Replan** (`adaptive_replan`)
- [x] **AI Security Reasoning** (`reasoning`)
- [x] **Verify Evidence Citations** (`verifier`)
- [x] **Adapt Brief Tone** (`communication`)
- [x] **Compile Hunt Report** (`report`)

---

## 📥 Phase 2: Ingestion & Normalization
This phase validates the collection, parsing, and filtering of telemetry data.

- **Telemetry Source:** wazuh
- **Ingestion Status & Diagnostics:**
- Records fetched: 21
- Total live-SIEM matches before result cap: 240
- Records analyzed after dedup: 18


### 🔍 SIEM Queries Executed
```
{"query":{"simple_query_string":{"query":"port scanning advanced scanner softperfect nmap accessible 3389","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","agent.name","decoder.name","location"],"default_operator":"or"}}}
```

### 🛡️ Guardrail Sentinel Scan
✅ **Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 18 records)

---

## 🔌 Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### 🎯 Sigma Detections
No static Sigma rule matched any of the 18 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### 📡 Threat Intelligence Enrichment
✅ No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### ⚠️ Telemetry Coverage Gaps
**ATT&CK technique testability:** `partial` — 1 covered, 1 partial, 0 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `partial` | medium | observed relevant device type(s) network, but not the required event category |
| Process Creation | `covered` | high | observed required event categories: process |

**Observed device types:** `{"network": 18}`

**Observed event categories:** `{"authentication": 3, "email": 1, "file": 8, "process": 6}`


⚠️ **Coverage gaps and health alerts:**

- ATT&CK T1046 telemetry `Network Traffic` is partial: observed relevant device type(s) network, but not the required event category.


---

## 🔎 Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### ⚙️ Analysis Reliability
✅ **Model reasoning completed and validated.** Mode: `model`; attempts: `1`.

### 📝 Security Findings
- [✓ hard-evidence] Evidence of Nmap scripting engine usage detected via web server 404 error (evidence: full log: 172.20.0.5 - - [27/Jul/2026:11:40:42 +0000] "GET /nmaplowercheck1785152442 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"; ref: 0)

### 🧐 Verifier / Critic Validation
✅ **Passed:** All cited references validated successfully. The verifier confirmed that all `1` evidence citations (`ref: N`) point to valid records in the processed logs.

### 📊 Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-27T11:40:42.685Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.5",
    "source_file": "wazuh-alerts-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:42.685Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"GET\", \"srcip\": \"172.20.0.5\", \"url\": \"/nmaplowercheck1785152442\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.5 - - [27/Jul/2026:11:40:42 +0000] \\\"GET /nmaplowercheck1785152442 HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1785152442.8711580\", \"input\": {\"type…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-27T11:40:13.506Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.506Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31169,\\\"title\\\":\\\"Ensure default group for the root account is GID 0.\\\",\\\"description\\\":\\\"The usermod command can be used to specify which group the root account belongs to. This affec…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-27T11:40:13.261Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:13.261Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31145,\\\"title\\\":\\\"Ensure SSH AllowTcpForwarding is disabled.\\\",\\\"description\\\":\\\"SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server…"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-27T11:40:12.985Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:12.985Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31118,\\\"title\\\":\\\"Ensure rsyslog is not configured to receive logs from a remote client.\\\",\\\"description\\\":\\\"RSyslog supports the ability to receive messages from remote hosts, thus ac…"
  },
  {
    "ref": 4,
    "timestamp": "2026-07-27T11:40:12.529Z",
    "host": "linux-victim",
    "event": "sca",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-archives-4.x-2026.07.27",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-27T11:40:12.529Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.4\", \"name\": \"linux-victim\"}, \"decoder\": {\"name\": \"sca\"}, \"full_log\": \"{\\\"type\\\":\\\"check\\\",\\\"id\\\":579033988,\\\"policy\\\":\\\"CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.\\\",\\\"policy_id\\\":\\\"cis_amazon_linux_2023\\\",\\\"check\\\":{\\\"id\\\":31073,\\\"title\\\":\\\"Ensure rpcbind is not installed or the rpcbind services are masked.\\\",\\\"description\\\":\\\"The rpcbind utility maps RPC services to the ports on which they listen. RPC p…"
  }
]
```

---

## 🚀 Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### 📢 Audience-Tailored Brief
> SOC analyst brief: The logs show a single record with evidence of Nmap scripting engine usage (404 error) but no process creation of known scanners or network traffic patterns matching port scanning. The hypothesis is partially supported by the Nmap scripting engine detection but lacks critical indicators like process execution of scanners or TCP SYN flows. Verify cited records and the verifier result before containment.

### 🛠️ Actionable Recommendations
1. Check Wazuh logs for process creation events (Sysmon 1) with command lines containing 'nmap.exe', 'advanced_ip_scanner.exe', or 'softperfect network scanner' to identify scanner executions.
2. Verify network traffic flows using Sysmon Event ID 3 (NetworkConnect) for rapid TCP SYN connections to ports 3389, 445, 5985/5986, 389.
3. Review CIS benchmark compliance checks for SSH and rsyslog configurations to identify potential misconfigurations that could be exploited during service discovery.

### 📐 Proposed Detection Rule
_No rule proposal generated for this hunt._

---

## 🔄 Phase 6: Lifecycle Case Management & Feedback
This phase tracks the operational lifecycle of the hunt and feeds findings back into the platform.

### 🎟️ Case & Investigation Tracking
No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)

### 📈 Continuous Learning & Feedback
Analyst feedback is logged to improve the on-prem reasoning models. Use the `/feedback` endpoint to rate this hunt:
```bash
curl -X POST http://localhost:8200/feedback \
  -H 'Authorization: Bearer <ORCHESTRATOR_API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"hunt_id": "07f57a31-676d-4022-8ef7-a0d3ff5dd465", "rating": "up/down/corrected", "correction": "Provide notes if rating is corrected"}'
```

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
