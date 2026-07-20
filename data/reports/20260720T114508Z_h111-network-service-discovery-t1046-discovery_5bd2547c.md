> ## 📋 Executive Summary Cover
>
> **What was investigated:** Network Service Discovery activity (Discovery),
> initiated 2026-07-20 11:45 UTC.
>
> **Bottom line:** [⚠ circumstantial] No deterministic detection match was produced; the model reasoning response was unavailable, so this hunt is inconclusive. (evidence: Histogram covers 2 processed records: {"Web server 400 error code."…
>
> **Analyst / requested by:** analyst
> **Full technical detail follows below.**

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

- **Hunt ID:** `5bd2547c-1b1a-4e01-beef-4716227ce22f`
- **Generated:** 2026-07-20T11:45:08.610219 UTC
- **Hypothesis ID:** H111
- **MITRE ATT&CK:** T1046 — Network Service Discovery (Discovery)
- **Log Source:** wazuh

## Hypothesis

An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

## Log Ingestion Diagnostics

- Records fetched: 4
- Total live-SIEM matches before result cap: 4
- Records analyzed after dedup: 2


## Executive Summary

Executive brief: Degraded analysis: the local reasoning model returned no final response. This report contains deterministic telemetry evidence only and requires analyst review. No automated response action is taken by THOS.

## MITRE ATT&CK Coverage

- **Technique:** Network Service Discovery (`T1046`)
- **Tactic:** Discovery
- **Description:** Network Service Discovery. Referenced by 2 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are using AI-powered tools to autonomously scan network infrastructure and enumerate high-value databases by executing thousands".
- **Typical data sources:** Network Traffic, Process Creation

_Note: this technique's canonical MITRE name/tactic come from THOS's base-technique reference table; the description is grounded in this platform's own hunting-hypothesis data, not invented._

## Queries Executed

```
{"query":{"simple_query_string":{"query":"port scanning advanced scanner softperfect nmap accessible 3389","fields":["full_log^3","rule.description^2","rule.groups","rule.mitre.id","rule.mitre.technique","agent.name","decoder.name","location"],"default_operator":"or"}}}
```

## Sigma Detections

No static Sigma rule matched any of the 2 analyzed record(s) for this hunt. (See Queries Executed / Sample Log Evidence below for what was actually searched.)

## Findings

- [⚠ circumstantial] No deterministic detection match was produced; the model reasoning response was unavailable, so this hunt is inconclusive. (evidence: Histogram covers 2 processed records: {"Web server 400 error code.": 2}; ref: histogram)

## Recommendations

- Verify Ollama model availability and response logs.
- Re-run this hunt after the model returns a non-empty response.
- Review the cited deterministic records before taking action.

## Detection Rule Proposal

_No rule proposal generated for this hunt._

## Sample Log Evidence

```json
[{'timestamp': '2026-07-20T11:28:52.925Z', 'host': 'linux-victim', 'user': '', 'event': 'Web server 400 error code.', 'detail': '{"@timestamp": "2026-07-20T11:28:52.925Z", "agent": {"id": "027", "ip": "172.20.0.5", "name": "linux-victim"}, "data": {"id": "404", "protocol": "GET", "srcip": "172.20.0.2", "url": "/HNAP1"}, "decoder": {"name": "web-accesslog"}, "full_log": "172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] \\"GET /HNAP1 HTTP/1.1\\" 404 3464 \\"-\\" \\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\" \\"-\\"", "id": "1784546932.2853983", "input": {"type": "log"}, "location": "/var/log/nginx/access.log", "manager": {"name": "wazuh.manager"}, "rule": {"description": "Web server 400 error code.", "firedtimes": 3, "gdpr": ["IV_35.7.d"], "groups": ["web", "accesslog", "attack"], "id": "31101", "level": 5, "mail": false, "nist_800_53": ["SA.11", "SI.4"], "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]}, "timestamp": "2026-07-20T11:28:52.925+0000"}', 'src_ip': '172.20.0.2', 'dst_ip': '', 'source_file': 'wazuh-alerts-4.x-2026.07.20', 'source_type': 'wazuh', '_wazuh_id': 'tRFJf58BqBZh3Lw0S5w1', '_raw': {'agent': {'ip': '172.20.0.5', 'name': 'linux-victim', 'id': '027'}, 'manager': {'name': 'wazuh.manager'}, 'data': {'protocol': 'GET', 'srcip': '172.20.0.2', 'id': '404', 'url': '/HNAP1'}, 'rule': {'firedtimes': 3, 'mail': False, 'level': 5, 'pci_dss': ['6.5', '11.4'], 'tsc': ['CC6.6', 'CC7.1', 'CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'], 'description': 'Web server 400 error code.', 'groups': ['web', 'accesslog', 'attack'], 'id': '31101', 'nist_800_53': ['SA.11', 'SI.4'], 'gdpr': ['IV_35.7.d']}, 'decoder': {'name': 'web-accesslog'}, 'full_log': '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /HNAP1 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"', 'input': {'type': 'log'}, '@timestamp': '2026-07-20T11:28:52.925Z', 'location': '/var/log/nginx/access.log', 'id': '1784546932.2853983', 'timestamp': '2026-07-20T11:28:52.925+0000'}}, {'timestamp': '2026-07-20T11:28:52.912Z', 'host': 'linux-victim', 'user': '', 'event': 'Web server 400 error code.', 'detail': '{"@timestamp": "2026-07-20T11:28:52.912Z", "agent": {"id": "027", "ip": "172.20.0.5", "name": "linux-victim"}, "data": {"id": "404", "protocol": "GET", "srcip": "172.20.0.2", "url": "/nmaplowercheck1784546931"}, "decoder": {"name": "web-accesslog"}, "full_log": "172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] \\"GET /nmaplowercheck1784546931 HTTP/1.1\\" 404 3464 \\"-\\" \\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\" \\"-\\"", "id": "1784546932.2852957", "input": {"type": "log"}, "location": "/var/log/nginx/access.log", "manager": {"name": "wazuh.manager"}, "rule": {"description": "Web server 400 error code.", "firedtimes": 1, "gdpr": ["IV_35.7.d"], "groups": ["web", "accesslog", "attack"], "id": "31101", "level": 5, "mail": false, "nist_800_53": ["SA.11", "SI.4"], "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]}, "timestamp": "2026-07-20T11:28:52.912+0000"}', 'src_ip': '172.20.0.2', 'dst_ip': '', 'source_file': 'wazuh-alerts-4.x-2026.07.20', 'source_type': 'wazuh', '_wazuh_id': 'sxFJf58BqBZh3Lw0S5w1', '_raw': {'agent': {'ip': '172.20.0.5', 'name': 'linux-victim', 'id': '027'}, 'manager': {'name': 'wazuh.manager'}, 'data': {'protocol': 'GET', 'srcip': '172.20.0.2', 'id': '404', 'url': '/nmaplowercheck1784546931'}, 'rule': {'firedtimes': 1, 'mail': False, 'level': 5, 'pci_dss': ['6.5', '11.4'], 'tsc': ['CC6.6', 'CC7.1', 'CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'], 'description': 'Web server 400 error code.', 'groups': ['web', 'accesslog', 'attack'], 'id': '31101', 'nist_800_53': ['SA.11', 'SI.4'], 'gdpr': ['IV_35.7.d']}, 'decoder': {'name': 'web-accesslog'}, 'full_log': '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /nmaplowercheck1784546931 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"', 'input': {'type': 'log'}, '@timestamp': '2026-07-20T11:28:52.912Z', 'location': '/var/log/nginx/access.log', 'id': '1784546932.2852957', 'timestamp': '2026-07-20T11:28:52.912+0000'}}]
```

---
*Generated by THOS (On-Prem AI Threat Hunting Platform) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
