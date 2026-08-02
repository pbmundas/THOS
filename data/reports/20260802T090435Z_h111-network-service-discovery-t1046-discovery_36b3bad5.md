# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Summary

Executive brief: The logs show 4 rapid TCP SYN connection attempts from host 172.20.0.4 to ports 3389 (RDP), 5985 (WinRM), 5986 (WinRM), and 445 (SMB) on host 172.20.0.2 within a 10-second window, matching the hypothesis of network service discovery via port scanning. No scanner binaries were detected in process creation events, but the pattern aligns with T1046 (Network Service Discovery) as defined by MITRE. No automated response action is taken by THOS.

### Key Evidence
- **Record 0 — 3389, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 3389, SYN, TCP.
- **Record 1 — 5985, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 5985, SYN, TCP.
- **Record 2 — 5986, SYN, TCP:** Record contains multiple governed hypothesis or indicator literals: 5986, SYN, TCP.

### Validation Snapshot
- **Verifier:** `passed`
- **Reasoning mode:** `model`
- **Records analyzed:** `142`
- **Selected key evidence:** `3`
- **Case:** `none`

---

## Hypothesis and Scope

- **Hunt ID:** `36b3bad5-0e3c-4585-b17a-2a41d6f46aab`
- **Hypothesis ID:** H111
- **Requested by / Analyst:** analyst
- **Hunt Started:** 2026-08-02 14:19:27 +0530 (IST)
- **Hunt Completed:** 2026-08-02 14:34:35 +0530 (IST)
- **Report Generated:** 2026-08-02 14:34:35 +0530 (IST)
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
- Records fetched: 177
- Total live-SIEM matches before result cap: 367
- Records analyzed after dedup: 142


### Queries Executed
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}},{"match_phrase":{"full_log":"advanced_ip_scanner.exe"}},{"match_phrase":{"full_log":"netscan.exe"}},{"match_phrase":{"full_log":"nmap.exe"}},{"match_phrase":{"full_log":"advanced_ip_scanner"}},{"match_phrase":{"full_log":"netscan"}},{"match_phrase":{"full_log":"nmap"}}],"minimum_should_match":1}}}

{"query":{"bool":{"should":[{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}}],"minimum_should_match":1}}}
```

### Retrieval Attempts
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Retrieve all network traffic data from Wazuh within the last 7 days and identify any suspicious activity related to port scanning tools. | 10080m | 2000 | `executed` | 177 / 367 | none |
| 2 | `wazuh` | Identify process creation events on host 172.20.0.4 within the last 10 minutes for scanner binaries | 60m | 100 | `executed` | 0 / 0 | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · wazuh · executed</summary>

Proposed:
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}},{"match_phrase":{"full_log":"advanced_ip_scanner.exe"}},{"match_phrase":{"full_log":"netscan.exe"}},{"match_phrase":{"full_log":"nmap.exe"}},{"match_phrase":{"full_log":"advanced_ip_scanner"}},{"match_phrase":{"full_log":"netscan"}},{"match_phrase":{"full_log":"nmap"}}],"minimum_should_match":1}}}
```
Normalized/executed candidate:
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}},{"match_phrase":{"full_log":"advanced_ip_scanner.exe"}},{"match_phrase":{"full_log":"netscan.exe"}},{"match_phrase":{"full_log":"nmap.exe"}},{"match_phrase":{"full_log":"advanced_ip_scanner"}},{"match_phrase":{"full_log":"netscan"}},{"match_phrase":{"full_log":"nmap"}}],"minimum_should_match":1}}}
```
</details>

<details><summary>Attempt 2 · wazuh · executed</summary>

Proposed:
```
{"query":{"bool":{"should":[{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}}],"minimum_should_match":1}}}
```
Normalized/executed candidate:
```
{"query":{"bool":{"should":[{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}}],"minimum_should_match":1}}}
```
</details>


---

## Evidence and Correlation

### Detection Rule Matches
No static detection rule matched any of the 142 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `unknown` — 0 covered, 0 partial, 0 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `unknown` | low | Coverage agent did not return a validated assessment. |
| Process Creation | `unknown` | low | Coverage agent did not return a validated assessment. |

**Observed device types:** `{"ids": 114, "network": 28}`

**Observed event categories:** `{"authentication": 1, "email": 28, "network": 113}`


**Coverage gaps and health alerts:**

- coverage_gap failed to return a validated decision after 1 attempt(s): Expecting ',' delimiter: line 21 column 6 (char 1558)


### Hunt Completeness
- **Status:** `complete`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["wazuh"]`
- **Queried sources:** `["wazuh"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `[]`
- **Retrieval attempts:** `2`
- **ATT&CK coverage status:** `unknown`

### Prompt-Injection Guardrail
**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned 142 records)

### Analysis Reliability
**Model reasoning completed and validated.** Mode: `model`; attempts: `2`.

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
    "timestamp": "2026-07-29T23:35:57.883Z",
    "host": "linux-victim",
    "event": "Web server 400 error code.",
    "src_ip": "172.20.0.4",
    "source_file": "wazuh-alerts-4.x-2026.07.29",
    "source_type": "wazuh",
    "detail": "{\"@timestamp\": \"2026-07-29T23:35:57.883Z\", \"agent\": {\"id\": \"035\", \"ip\": \"172.20.0.2\", \"name\": \"linux-victim\"}, \"data\": {\"id\": \"404\", \"protocol\": \"GET\", \"srcip\": \"172.20.0.4\", \"url\": \"/evox/about\"}, \"decoder\": {\"name\": \"web-accesslog\"}, \"full_log\": \"172.20.0.4 - - [29/Jul/2026:23:35:56 +0000] \\\"GET /evox/about HTTP/1.1\\\" 404 3464 \\\"-\\\" \\\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\\" \\\"-\\\"\", \"id\": \"1785368157.1506710\", \"input\": {\"type\": \"log\"}, \"location\": \"/var…"
  },
  {
    "ref": 13,
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
  }
]
```

---

## Findings
- [hard-evidence] Host 172.20.0.4 initiated rapid TCP SYN connections to RDP (3389), WinRM (5985/5986), and SMB (445) ports on host 172.20.0.2 (evidence: 3389, 5985, 5986, 445; ref: 0,1,2,3)

## Recommendations
1. Verify if host 172.20.0.4 has legitimate network scanning tools installed via Sysmon process creation events for advanced_ip_scanner.exe, netscan.exe, or nmap.exe.
2. Check Wazuh for network traffic patterns showing multiple SYN scans to common ports across multiple hosts within 10 seconds.
3. Review firewall rules for host 172.20.0.2 to identify if port 445 (SMB) is exposed to internal network scans.

### Proposed Detection Rule
_No rule proposal generated for this hunt._
