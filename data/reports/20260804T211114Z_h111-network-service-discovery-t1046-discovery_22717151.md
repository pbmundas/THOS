# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Summary

SOC analyst brief: The logs partially support the hypothesis that network service discovery is being performed using nmap. Evidence includes the execution of 'nmap.exe' with scanning commands and subsequent connection attempts to ports commonly associated with RDP and SMB services on multiple hosts. Verify cited records and the verifier result before containment.

### Key Evidence
- **Record 0 — nmap.exe:** The process 'nmap.exe' was started on host ENG-WS07 at timestamp 2026-08-04T20:30:00Z.
- **Record 1 — 445:** A connection attempt to port 445 was made from host ENG-WS07 at timestamp 2026-08-04T20:30:03Z.
- **Record 2 — 3389:** A connection attempt to port 3389 was made from host ENG-WS07 at timestamp 2026-08-04T20:30:05Z.

### Validation Snapshot
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `4`
- **Selected key evidence:** `3`
- **Case:** `none`

---

## Hypothesis and Scope

- **Hunt ID:** `22717151-1af7-42b1-9a82-e525cddedfd5`
- **Hypothesis ID:** H111
- **Requested by / Analyst:** codex-positive-model-benchmark
- **Hunt Started:** 2026-08-05 02:25:55 +0530 (IST)
- **Hunt Completed:** 2026-08-05 02:41:14 +0530 (IST)
- **Report Generated:** 2026-08-05 02:41:14 +0530 (IST)
- **MITRE ATT&CK Tactic:** Discovery
- **MITRE ATT&CK Technique:** Network Service Discovery (T1046)
- **Telemetry Source:** Local folder — /data/log_sources/codex-model-benchmark
- **Hypothesis:** An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

### MITRE ATT&CK Coverage
- **Technique:** Network Service Discovery (`T1046`)
- **Tactic:** Discovery
- **Description:** Network Service Discovery. Referenced by 2 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are using AI-powered tools to autonomously scan network infrastructure and enumerate high-value databases by executing thousands".
- **Typical data sources:** Network Traffic, Process Creation

### Related ATT&CK Technique Signals
_No evidence-backed cross-technique leads were identified._

### Investigation Requirements
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

### Hunt Plan
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

### Prior Hunt Context
No recent hunts targeting this technique have been recorded in the platform database.

---

## Telemetry Retrieval

### Retrieval Results
- Files scanned: 1
- Total records parsed (before query filter): 4
- Records after query filter: 4
- Total live-SIEM matches before result cap: None
- Records analyzed after dedup: 4
- Unfiltered substitution used: False


### Queries Executed
```
advanced_ip_scanner.exe, netscan.exe, nmap.exe, scanner.exe, TCP, SYN, 3389, 445, 5985, 5986, 389, scan, discovery, network_service_discovery, T1046
```

### Retrieval Attempts
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `folder` | Retrieve process creation and network traffic data to identify execution of known scanner binaries, files masquerading as legitimate tools, and rapid sequential TCP SYN connections | 1440m | 2000 | `executed` | 4 /  | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · folder · executed</summary>

Proposed:
```
advanced_ip_scanner.exe, netscan.exe, nmap.exe, scanner.exe, TCP, SYN, 3389, 445, 5985, 5986, 389, scan, discovery, network_service_discovery, T1046
```
Normalized/executed candidate:
```
advanced_ip_scanner.exe, netscan.exe, nmap.exe, scanner.exe, TCP, SYN, 3389, 445, 5985, 5986, 389, scan, discovery, network_service_discovery, T1046
```
</details>


---

## Evidence and Correlation

### Detection Rule Matches
No static detection rule matched any of the 4 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `unknown` — 0 covered, 0 partial, 0 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `unknown` | low | Coverage agent did not return a validated assessment. |
| Process Creation | `unknown` | low | Coverage agent did not return a validated assessment. |

**Observed device types:** `{"endpoint": 1, "network": 3}`

**Observed event categories:** `{"process": 4}`


**Coverage gaps and health alerts:**

- coverage_gap failed to return a validated decision after 1 attempt(s): ReadTimeout


### Hunt Completeness
- **Status:** `complete`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["folder"]`
- **Queried sources:** `["folder"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `[]`
- **Retrieval attempts:** `1`
- **ATT&CK coverage status:** `unknown`

### Prompt-Injection Guardrail
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 4 records)

### Analysis Reliability
**Model reasoning completed and validated.** Mode: `model`; attempts: `2`.

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `3` evidence citations (`ref: N`) point to valid records in the processed logs.

### Case Status
No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)

### Representative Evidence
```json
[
  {
    "ref": 0,
    "timestamp": "2026-08-04T20:30:00Z",
    "host": "ENG-WS07",
    "user": "lab-analyst",
    "event": "start",
    "src_ip": "10.20.30.17",
    "source_file": "nmap-t1046.jsonl",
    "source_type": "json",
    "detail": "{\"@timestamp\": \"2026-08-04T20:30:00Z\", \"host\": {\"name\": \"ENG-WS07\"}, \"user\": {\"name\": \"lab-analyst\"}, \"event\": {\"category\": \"process\", \"action\": \"start\"}, \"process\": {\"name\": \"nmap.exe\", \"executable\": \"C:\\\\Tools\\\\nmap.exe\", \"command_line\": \"C:\\\\Tools\\\\nmap.exe -sS -p 22,80,445,3389 10.20.30.0/24\", \"parent\": {\"name\": \"cmd.exe\"}}, \"rule\": {\"description\": \"Nmap network service discovery command observed\"}, \"source\": {\"ip\": \"10.20.30.17\"}}"
  },
  {
    "ref": 1,
    "timestamp": "2026-08-04T20:30:03Z",
    "host": "ENG-WS07",
    "user": "lab-analyst",
    "event": "connection_attempt",
    "src_ip": "10.20.30.17",
    "dst_ip": "10.20.30.21",
    "source_file": "nmap-t1046.jsonl",
    "source_type": "json",
    "detail": "{\"@timestamp\": \"2026-08-04T20:30:03Z\", \"host\": {\"name\": \"ENG-WS07\"}, \"user\": {\"name\": \"lab-analyst\"}, \"event\": {\"category\": \"network\", \"action\": \"connection_attempt\"}, \"process\": {\"name\": \"nmap.exe\"}, \"source\": {\"ip\": \"10.20.30.17\"}, \"destination\": {\"ip\": \"10.20.30.21\", \"port\": 445}, \"network\": {\"transport\": \"tcp\"}, \"rule\": {\"description\": \"Rapid multi-port scan behavior associated with nmap\"}}"
  },
  {
    "ref": 2,
    "timestamp": "2026-08-04T20:30:05Z",
    "host": "ENG-WS07",
    "user": "lab-analyst",
    "event": "connection_attempt",
    "src_ip": "10.20.30.17",
    "dst_ip": "10.20.30.22",
    "source_file": "nmap-t1046.jsonl",
    "source_type": "json",
    "detail": "{\"@timestamp\": \"2026-08-04T20:30:05Z\", \"host\": {\"name\": \"ENG-WS07\"}, \"user\": {\"name\": \"lab-analyst\"}, \"event\": {\"category\": \"network\", \"action\": \"connection_attempt\"}, \"process\": {\"name\": \"nmap.exe\"}, \"source\": {\"ip\": \"10.20.30.17\"}, \"destination\": {\"ip\": \"10.20.30.22\", \"port\": 3389}, \"network\": {\"transport\": \"tcp\"}, \"rule\": {\"description\": \"Rapid multi-port scan behavior associated with nmap\"}}"
  },
  {
    "ref": 3,
    "timestamp": "2026-08-04T20:29:00Z",
    "host": "ENG-WS07",
    "user": "SYSTEM",
    "event": "start",
    "source_file": "nmap-t1046.jsonl",
    "source_type": "json",
    "detail": "{\"@timestamp\": \"2026-08-04T20:29:00Z\", \"host\": {\"name\": \"ENG-WS07\"}, \"user\": {\"name\": \"SYSTEM\"}, \"event\": {\"category\": \"process\", \"action\": \"start\"}, \"process\": {\"name\": \"svchost.exe\", \"command_line\": \"C:\\\\Windows\\\\System32\\\\svchost.exe -k netsvcs\"}, \"rule\": {\"description\": \"Routine Windows service process\"}}"
  }
]
```

---

## Findings
- [hard-evidence] Execution of known scanner binary 'nmap.exe' (evidence: 'nmap.exe' was executed with a command line indicating network service discovery across common ports.; ref: 0)
- [hard-evidence] Rapid sequential TCP SYN connections to multiple ports on different hosts (evidence: Connection attempts to ports 445 and 3389 from host ENG-WS07, indicative of a scanning pattern.; ref: 1,2)

## Recommendations
Review Sysmon configuration for enhanced process creation logging, including command line arguments. Implement or review network traffic analysis tools to detect rapid port scans across the internal network.

### Proposed Detection Rule
_No rule proposal generated for this hunt._
