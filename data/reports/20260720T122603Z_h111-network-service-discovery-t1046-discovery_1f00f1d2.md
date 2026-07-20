> ## 📋 Executive Summary Cover
>
> **What was investigated:** Network Service Discovery activity (Discovery),
> initiated 2026-07-20 12:26 UTC.
>
> **Bottom line:** [✓ hard-evidence] Nmap scanning activity detected via HTTP requests with Nmap Scripting Engine user-agent (evidence: full_log: '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /nmaplowercheck1784546931 HTTP/1.1" 404 346…
>
> **Analyst / requested by:** analyst
> **Full technical detail follows below.**

---

# Threat Hunt Report: H111 — Network Service Discovery (T1046) — Discovery

- **Hunt ID:** `1f00f1d2-0b0e-4cfb-99fe-f9f5d0975307`
- **Generated:** 2026-07-20T12:26:03.163999 UTC
- **Hypothesis ID:** H111
- **MITRE ATT&CK:** T1046 — Network Service Discovery (Discovery)
- **Log Source:** wazuh

## Hypothesis

An adversary is performing network service discovery by deploying port scanning tools such as Advanced IP Scanner, SoftPerfect Network Scanner, or nmap to identify accessible services including RDP (3389), SMB (445), WinRM (5985/5986), and LDAP (389) across the internal network. Look for execution of known scanner binaries (advanced_ip_scanner.exe, netscan.exe, nmap.exe), files masquerading as legitimate tools (e.g., scanner binary named as a different tool), and rapid sequential TCP SYN connections across multiple ports to many hosts. Network flow data showing a single host connecting to common service ports across many destinations is a key indicator.

## Log Ingestion Diagnostics

- Records fetched: 0
- Total live-SIEM matches before result cap: 0
- Records analyzed after dedup: 2


## Executive Summary

Executive brief: The logs show two 404 HTTP errors from a single source IP (172.20.0.2) to a web server (linux-victim), with URLs containing 'nmaplowercheck' and Nmap Scripting Engine user-agent strings. This matches the hypothesis of network service discovery via Nmap, as the URL patterns and user-agent indicate Nmap's scanning behavior. However, no actual port scanning activity was observed in network event logs (Sysmon, Security events), and the sample contains only web access logs, not network connection events. No automated response action is taken by THOS.

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

- [✓ hard-evidence] Nmap scanning activity detected via HTTP requests with Nmap Scripting Engine user-agent (evidence: full_log: '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /nmaplowercheck1784546931 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"'; ref: 0)
- [✓ hard-evidence] No Sysmon or Windows Security events indicate port scanning activity (evidence: Event-type histogram shows only Web server 400 errors (count: 2), with no Sysmon events (1, 2, 3, 7, 8, 10, 11, 13, 22) or Security events (4624, 4688, 4663, 5156) present in the analyzed records; ref: histogram)

## Recommendations

Check for Nmap activity via Sysmon event 3 (NetworkConnect) and Security event 4624 (logon with suspicious process) for Windows hosts; enable Sysmon to capture NetworkConnect events for non-Windows systems; review web-access logs for URLs with 'nmap' patterns; ensure Wazuh rules are configured to detect Nmap user-agent strings in HTTP logs

## Detection Rule Proposal

_No rule proposal generated for this hunt._

## Sample Log Evidence

```json
[{'timestamp': '2026-07-20T11:28:52.925Z', 'host': 'linux-victim', 'user': '', 'event': 'Web server 400 error code.', 'detail': '{"@timestamp": "2026-07-20T11:28:52.925Z", "agent": {"id": "027", "ip": "172.20.0.5", "name": "linux-victim"}, "data": {"id": "404", "protocol": "GET", "srcip": "172.20.0.2", "url": "/HNAP1"}, "decoder": {"name": "web-accesslog"}, "full_log": "172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] \\"GET /HNAP1 HTTP/1.1\\" 404 3464 \\"-\\" \\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\" \\"-\\"", "id": "1784546932.2853983", "input": {"type": "log"}, "location": "/var/log/nginx/access.log", "manager": {"name": "wazuh.manager"}, "rule": {"description": "Web server 400 error code.", "firedtimes": 3, "gdpr": ["IV_35.7.d"], "groups": ["web", "accesslog", "attack"], "id": "31101", "level": 5, "mail": false, "nist_800_53": ["SA.11", "SI.4"], "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]}, "timestamp": "2026-07-20T11:28:52.925+0000"}', 'src_ip': '172.20.0.2', 'dst_ip': '', 'source_file': 'wazuh-alerts-4.x-2026.07.20', 'source_type': 'wazuh', '_wazuh_id': 'tRFJf58BqBZh3Lw0S5w1', '_raw': {'agent': {'ip': '172.20.0.5', 'name': 'linux-victim', 'id': '027'}, 'manager': {'name': 'wazuh.manager'}, 'data': {'protocol': 'GET', 'srcip': '172.20.0.2', 'id': '404', 'url': '/HNAP1'}, 'rule': {'firedtimes': 3, 'mail': False, 'level': 5, 'pci_dss': ['6.5', '11.4'], 'tsc': ['CC6.6', 'CC7.1', 'CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'], 'description': 'Web server 400 error code.', 'groups': ['web', 'accesslog', 'attack'], 'id': '31101', 'nist_800_53': ['SA.11', 'SI.4'], 'gdpr': ['IV_35.7.d']}, 'decoder': {'name': 'web-accesslog'}, 'full_log': '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /HNAP1 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"', 'input': {'type': 'log'}, '@timestamp': '2026-07-20T11:28:52.925Z', 'location': '/var/log/nginx/access.log', 'id': '1784546932.2853983', 'timestamp': '2026-07-20T11:28:52.925+0000'}}, {'timestamp': '2026-07-20T11:28:52.912Z', 'host': 'linux-victim', 'user': '', 'event': 'Web server 400 error code.', 'detail': '{"@timestamp": "2026-07-20T11:28:52.912Z", "agent": {"id": "027", "ip": "172.20.0.5", "name": "linux-victim"}, "data": {"id": "404", "protocol": "GET", "srcip": "172.20.0.2", "url": "/nmaplowercheck1784546931"}, "decoder": {"name": "web-accesslog"}, "full_log": "172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] \\"GET /nmaplowercheck1784546931 HTTP/1.1\\" 404 3464 \\"-\\" \\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\\" \\"-\\"", "id": "1784546932.2852957", "input": {"type": "log"}, "location": "/var/log/nginx/access.log", "manager": {"name": "wazuh.manager"}, "rule": {"description": "Web server 400 error code.", "firedtimes": 1, "gdpr": ["IV_35.7.d"], "groups": ["web", "accesslog", "attack"], "id": "31101", "level": 5, "mail": false, "nist_800_53": ["SA.11", "SI.4"], "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]}, "timestamp": "2026-07-20T11:28:52.912+0000"}', 'src_ip': '172.20.0.2', 'dst_ip': '', 'source_file': 'wazuh-alerts-4.x-2026.07.20', 'source_type': 'wazuh', '_wazuh_id': 'sxFJf58BqBZh3Lw0S5w1', '_raw': {'agent': {'ip': '172.20.0.5', 'name': 'linux-victim', 'id': '027'}, 'manager': {'name': 'wazuh.manager'}, 'data': {'protocol': 'GET', 'srcip': '172.20.0.2', 'id': '404', 'url': '/nmaplowercheck1784546931'}, 'rule': {'firedtimes': 1, 'mail': False, 'level': 5, 'pci_dss': ['6.5', '11.4'], 'tsc': ['CC6.6', 'CC7.1', 'CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'], 'description': 'Web server 400 error code.', 'groups': ['web', 'accesslog', 'attack'], 'id': '31101', 'nist_800_53': ['SA.11', 'SI.4'], 'gdpr': ['IV_35.7.d']}, 'decoder': {'name': 'web-accesslog'}, 'full_log': '172.20.0.2 - - [20/Jul/2026:11:28:51 +0000] "GET /nmaplowercheck1784546931 HTTP/1.1" 404 3464 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" "-"', 'input': {'type': 'log'}, '@timestamp': '2026-07-20T11:28:52.912Z', 'location': '/var/log/nginx/access.log', 'id': '1784546932.2852957', 'timestamp': '2026-07-20T11:28:52.912+0000'}}]
```

---
*Generated by THOS (On-Prem AI Threat Hunting Platform) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
