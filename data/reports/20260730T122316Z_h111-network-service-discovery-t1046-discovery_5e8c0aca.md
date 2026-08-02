# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

## Summary

Executive brief: The logs show a single host (172.20.0.4) performing rapid TCP SYN scans against multiple target ports (3389, 5985, 5986, 445) on host 172.20.0.2 within a 10-second window, matching the hypothesis of network service discovery via port scanning. However, no process creation events for scanner binaries were captured due to Wazuh (Suricata) only monitoring network flows, not process activity. No automated response action is taken by THOS.

### Key Evidence
- **Record 0 — 3389, SYN, TCP:** A normalized network-flow record shows `172.20.0.4:65192` sending a TCP SYN to `172.20.0.2:3389`.
- **Record 1 — 5985, SYN, TCP:** A normalized network-flow record shows the same source socket sending a TCP SYN to `172.20.0.2:5985`.
- **Record 2 — 5986, SYN, TCP:** A normalized network-flow record shows the same source socket sending a TCP SYN to `172.20.0.2:5986`.

---

## Hypothesis and Scope

- **Hypothesis ID:** H111
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

---

## Telemetry Retrieval

### Retrieval Results
- Records fetched: 181
- Total live-SIEM matches before result cap: 375
- Records analyzed after dedup: 146


### Queries Executed
```
{"query":{"bool":{"should":[{"term":{"data.dest_port":"3389"}},{"term":{"data.dest_port":"445"}},{"term":{"data.dest_port":"5985"}},{"term":{"data.dest_port":"5986"}},{"term":{"data.dest_port":"389"}},{"term":{"data.dstport":"3389"}},{"term":{"data.dstport":"445"}},{"term":{"data.dstport":"5985"}},{"term":{"data.dstport":"5986"}},{"term":{"data.dstport":"389"}},{"term":{"data.flow.dest_port":"3389"}},{"term":{"data.flow.dest_port":"445"}},{"term":{"data.flow.dest_port":"5985"}},{"term":{"data.flow.dest_port":"5986"}},{"term":{"data.flow.dest_port":"389"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.process.name":"netscan.exe"}},{"match_phrase":{"data.process.name":"nmap.exe"}},{"match_phrase":{"data.process.name":"advanced_ip_scanner"}},{"match_phrase":{"data.process.name":"netscan"}},{"match_phrase":{"data.process.name":"nmap"}},{"match_phrase":{"data.command":"advanced_ip_scanner.exe"}},{"match_phrase":{"data.command":"netscan.exe"}},{"match_phrase":{"data.command":"nmap.exe"}},{"match_phrase":{"data.command":"advanced_ip_scanner"}},{"match_phrase":{"data.command":"netscan"}},{"match_phrase":{"data.command":"nmap"}},{"match_phrase":{"full_log":"advanced_ip_scanner.exe"}},{"match_phrase":{"full_log":"netscan.exe"}},{"match_phrase":{"full_log":"nmap.exe"}},{"match_phrase":{"full_log":"advanced_ip_scanner"}},{"match_phrase":{"full_log":"netscan"}},{"match_phrase":{"full_log":"nmap"}}],"minimum_should_match":1}}}
```

### Retrieval Attempts
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `wazuh` | Retrieve process creation events for known scanner binaries (nmap.exe, advanced_ip_scanner.exe, netscan.exe) within the last 14 days | 10080m | 2000 | `executed` | 181 / 375 | none |

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


---

## Evidence and Correlation

### Detection Rule Matches
No static detection rule matched any of the 146 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

### Threat Intelligence Enrichment
No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist.

### Telemetry Coverage Gaps
**ATT&CK technique testability:** `covered` — 1 covered, 0 partial, 1 unavailable of 2 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Network Traffic | `covered` | high | Suricata (Wazuh) captures network flows with source/destination IPs, ports, protocols, and TCP flags. Records 0-4 show TCP flows with source port 65192 (likely a scanner) connecting to ports 3389 (RDP), 5985 (WS-Management), 5986 (WS-Management), and 445 (SMB) on the target. These flows include critical fields for network service discovery (src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags). |
| Process Creation | `not_covered` | medium | Wazuh (Suricata) is an IDS/IPS solution that monitors network traffic but does not capture process creation events. The observed telemetry only includes network flows and HTTP requests (email category), with no process-level data. Process creation events require different telemetry (e.g., Windows Event Logs, Linux process monitors). |

**Observed device types:** `{"ids": 114, "network": 32}`

**Observed event categories:** `{"authentication": 1, "email": 32, "network": 113}`


**Coverage gaps and health alerts:**

- Wazuh (Suricata) does not collect process creation events; this requires a separate telemetry source (e.g., Windows Event Logs or Linux process monitors).


### Hunt Completeness
- **Status:** `complete_with_result_caps`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["wazuh"]`
- **Queried sources:** `["wazuh"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `["wazuh"]`
- **Retrieval attempts:** `1`
- **ATT&CK coverage status:** `covered`

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
- [hard-evidence] Host 172.20.0.4 initiated rapid TCP SYN scans against RDP (3389), WinRM (5985/5986), and SMB (445) ports on host 172.20.0.2 (evidence: src_ip: 172.20.0.4, dest_ip: 172.20.0.2, src_port: 65192, dest_port: 3389 (record:0), dest_port: 5985 (record:1), dest_port: 5986 (record:2), dest_port: 445 (record:3); ref: 0,1,2,3)

## Recommendations
1. Enable Sysmon process creation event collection for Windows hosts to detect scanner binaries (nmap.exe, advanced_ip_scanner.exe, netscan.exe)
2. Configure Wazuh to capture process creation events via GPO setting 'Audit process creation' (Policy ID: 1001)
3. Implement a detection rule for TCP SYN scans against multiple ports (3389, 445, 5985, 5986) with a short time window (e.g., 10 seconds) to identify rapid service discovery

### Proposed Detection Rule
_No rule proposal generated for this hunt._
