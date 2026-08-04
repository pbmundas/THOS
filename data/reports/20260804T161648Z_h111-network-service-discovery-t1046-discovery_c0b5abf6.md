# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Summary

Executive brief: The logs show 10 rapid TCP SYN connection attempts to well-known ports (3389, 5985, 5986, 445) from a single source IP (172.20.0.4) to a single destination IP (172.20.0.2) within a 10-second window, matching the hypothesis of network service discovery. However, no process creation events or scanner binaries were observed, and the Wazuh connector only captures network flows without process telemetry. No automated response action is taken by THOS.

### Key Evidence
- **Record 0 — 3389, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 3389, SYN, TCP.
- **Record 1 — 5985, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 5985, SYN, TCP.
- **Record 2 — 5986, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 5986, SYN, TCP.

### Validation Snapshot
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `15`
- **Selected key evidence:** `3`
- **Case:** `none`

---

## Hypothesis and Scope

- **Hunt ID:** `c0b5abf6-82b8-4de6-8470-2434870e2d59`
- **Hypothesis ID:** H111
- **Requested by / Analyst:** analyst
- **Hunt Started:** 2026-08-04 21:40:32 +0530 (IST)
- **Hunt Completed:** 2026-08-04 21:46:48 +0530 (IST)
- **Report Generated:** 2026-08-04 21:46:48 +0530 (IST)
- **MITRE ATT&CK Tactic:** Discovery
- **MITRE ATT&CK Technique:** Network Service Discovery (T1046)
- **Telemetry Source:** wazuh
- **Hypothesis:** An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

### MITRE ATT&CK Coverage
- **Technique:** Network Service Discovery (`T1046`)
- **Tactic:** Discovery
- **Description:** Network Service Discovery. Referenced by 2 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are using AI-powered tools to autonomously scan network infrastructure and enumerate high-value databases by executing thousands".
- **Typical data sources:** Network Traffic, Process Creation

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
- Records fetched: 15
- Total live-SIEM matches before result cap: 15
- Records analyzed after dedup: 15


### Queries Executed
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}}],"minimum_should_match":1}}}
```

### Retrieval Attempts
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Validate that each required telemetry category is available in the selected source set. Run a high-precision direct-evidence query using only literal hypothesis and governed ATT&CK | 10080m | 2000 | `executed` | 15 / 15 | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · wazuh · executed</summary>

Proposed:
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}}],"minimum_should_match":1}}}
```
Normalized/executed candidate:
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}}],"minimum_should_match":1}}}
```
</details>


---

## Evidence and Correlation

### Detection Rule Matches
No static detection rule matched any of the 15 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `covered` — 1 covered, 0 partial, 1 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `covered` | high | The Wazuh connector returns network flow records with source and destination IPs, ports, and protocol details. Each record contains the required fields for network service discovery (e.g., src_ip, dest_ip, src_port, dest_port, proto). The observed records (record:0 to record:3) show multiple TCP connections to well-known ports (3389, 5985, 5986, 445) which are relevant for service discovery. The W |
| Process Creation | `not_covered` | high | The Wazuh connector does not provide process creation telemetry. The observed records are network flows, not process events. Process creation data would require a different telemetry source (e.g., Windows Event Logs or Linux process monitoring). The connector diagnostics show only network traffic data (last_record_count: 15, all in 'network' category). |

**Observed device types:** `{"ids": 15}`

**Observed event categories:** `{"network": 15}`


**Coverage gaps and health alerts:**

- Wazuh connector does not collect process creation telemetry


### Hunt Completeness
- **Status:** `complete`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["wazuh"]`
- **Queried sources:** `["wazuh"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `[]`
- **Retrieval attempts:** `1`
- **ATT&CK coverage status:** `covered`

### Prompt-Injection Guardrail
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 15 records)

### Analysis Reliability
**Model reasoning completed and validated.** Mode: `model`; attempts: `1`.

### Verifier / Critic Validation
**Passed:** All cited references validated successfully. The verifier confirmed that all `4` evidence citations (`ref: N`) point to valid records in the processed logs.

### Case Status
No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)

### Representative Evidence
```json
[
  {
    "ref": 0,
    "timestamp": "2026-07-29T23:36:05.953Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:36:05.953Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.2\", \"dest_port\": \"3389\", \"event_type\": \"flow\", \"flow\": {\"age\": \"0\", \"alerted\": \"true\", \"bytes_toclient\": \"54\", \"bytes_toserver\": \"58\", \"end\": \"2026-07-29T23:35:49.922355+0000\", \"pkts_toclient\": \"1\", \"pkts_toserver\": \"1\", \"reason\": \"timeout\", \"start\": \"2026-07-29T23:35:49.922249+0000\", \"state\": \"closed\"}, \"flow_id\": \"1427755353602217.000000\", \"in_iface\": \"et…"
  },
  {
    "ref": 5,
    "timestamp": "2026-07-29T23:35:52.912Z",
    "host": "linux-victim",
    "event": "Suricata: Alert - PURPLE LAB TCP reconnaissance",
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:35:52.912Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"alert\": {\"action\": \"allowed\", \"category\": \"Attempted Information Leak\", \"gid\": \"1\", \"rev\": \"1\", \"severity\": \"2\", \"signature\": \"PURPLE LAB TCP reconnaissance\", \"signature_id\": \"9000001\"}, \"dest_ip\": \"172.20.0.2\", \"dest_port\": \"5986\", \"direction\": \"to_server\", \"event_type\": \"alert\", \"flow\": {\"bytes_toclient\": \"0\", \"bytes_toserver\": \"58\", \"dest_ip\": \"172.20.0.2\", \"dest_port\": \"59…"
  },
  {
    "ref": 1,
    "timestamp": "2026-07-29T23:36:04.328Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:36:04.328Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.2\", \"dest_port\": \"5985\", \"event_type\": \"flow\", \"flow\": {\"age\": \"0\", \"alerted\": \"true\", \"bytes_toclient\": \"54\", \"bytes_toserver\": \"58\", \"end\": \"2026-07-29T23:35:49.938384+0000\", \"pkts_toclient\": \"1\", \"pkts_toserver\": \"1\", \"reason\": \"timeout\", \"start\": \"2026-07-29T23:35:49.938346+0000\", \"state\": \"closed\"}, \"flow_id\": \"1496894451832177.000000\", \"in_iface\": \"et…"
  },
  {
    "ref": 2,
    "timestamp": "2026-07-29T23:36:02.361Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:36:02.361Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.2\", \"dest_port\": \"5986\", \"event_type\": \"flow\", \"flow\": {\"age\": \"0\", \"alerted\": \"true\", \"bytes_toclient\": \"54\", \"bytes_toserver\": \"58\", \"end\": \"2026-07-29T23:35:49.955070+0000\", \"pkts_toclient\": \"1\", \"pkts_toserver\": \"1\", \"reason\": \"timeout\", \"start\": \"2026-07-29T23:35:49.955044+0000\", \"state\": \"closed\"}, \"flow_id\": \"1568609944793573.000000\", \"in_iface\": \"et…"
  },
  {
    "ref": 3,
    "timestamp": "2026-07-29T23:36:02.234Z",
    "host": "linux-victim",
    "event": "json",
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "source_file": "wazuh-archives-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:36:02.234Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"dest_ip\": \"172.20.0.2\", \"dest_port\": \"445\", \"event_type\": \"flow\", \"flow\": {\"age\": \"0\", \"alerted\": \"true\", \"bytes_toclient\": \"54\", \"bytes_toserver\": \"58\", \"end\": \"2026-07-29T23:35:49.920935+0000\", \"pkts_toclient\": \"1\", \"pkts_toserver\": \"1\", \"reason\": \"timeout\", \"start\": \"2026-07-29T23:35:49.920929+0000\", \"state\": \"closed\"}, \"flow_id\": \"1422088277254604.000000\", \"in_iface\": \"eth…"
  }
]
```

---

## Findings
- [hard-evidence] Rapid sequential TCP SYN connections to multiple well-known service ports (3389, 5985, 5986, 445) from a single source IP to a single destination IP (evidence: dest_port: 3389, 5985, 5986, 445; src_ip: 172.20.0.4; dest_ip: 172.20.0.2; tcp_syn: true; ref: 0-3)

## Recommendations
1. Verify process creation events for the source host (172.20.0.4) using Windows Event Logs (Event ID 4684) or Sysmon (Event ID 1102) to detect potential scanner tool execution.
2. Configure Wazuh to capture process creation telemetry via Sysmon by enabling the 'process_creation' event type in the Wazuh connector configuration.
3. Implement network flow monitoring with a 10-second window to detect rapid port scanning activity across multiple hosts.

### Proposed Detection Rule
_No rule proposal generated for this hunt._
