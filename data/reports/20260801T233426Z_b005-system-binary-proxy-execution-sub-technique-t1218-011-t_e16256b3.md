# Threat Hunt Report: B005 — System Binary Proxy Execution (sub-technique T1218.011) (T1218.011) — Execution

## Summary

SOC analyst brief: The logs show evidence of rundll32.exe being used for suspicious activity (EventID-1 and EventID-10), but no direct malicious code execution or unsigned DLLs were observed. The hypothesis is partially supported by 3 records matching detection rules for rundll32 usage, though the absence of unsigned DLLs or network connections suggests limited malicious intent. Verify cited records and the verifier result before containment.

### Key Evidence
- **Record 254 — rundll32.exe, Rundll32, dll:** Record contains multiple governed hypothesis or indicator literals: rundll32.exe, Rundll32, dll.
- **Record 273 — rundll32.exe, Rundll32, dll:** Record contains multiple governed hypothesis or indicator literals: rundll32.exe, Rundll32, dll.
- **Record 274 — rundll32.exe, Rundll32:** Record contains multiple governed hypothesis or indicator literals: rundll32.exe, Rundll32.

---

## Hypothesis and Scope

- **Hypothesis ID:** B005
- **MITRE ATT&CK Tactic:** Execution
- **MITRE ATT&CK Technique:** System Binary Proxy Execution (sub-technique T1218.011) (T1218.011)
- **Telemetry Source:** Local folder — /data/log_sources
- **Hypothesis:** Adversaries are exploiting the native Windows process Rundll32 in order to execute malicious code and bypass application control solutions. The scope of this hunt could become too wide without defining an area of focus. For one hunt, it might be best to pursue one category of visibility such as command,k process, or module monitoring.

### MITRE ATT&CK Coverage
- **Technique:** System Binary Proxy Execution (sub-technique T1218.011) (`T1218.011`)
- **Tactic:** Execution
- **Description:** System Binary Proxy Execution. Referenced by 1 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "Adversaries are exploiting the native Windows process Rundll32 in order to execute malicious code and bypass application control solutions.".
- **Typical data sources:** Process Creation

### Investigation Requirements
- **Title:** Adversaries are exploiting the native Windows process Rundll32 in order to execute malicious code and bypass application control solutions.
- **Required ATT&CK data sources:** Process Creation
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

## Telemetry Retrieval

### Retrieval Results
- Files scanned: 54
- Total records parsed (before query filter): 3746
- Records after query filter: 371
- Total live-SIEM matches before result cap: None
- Records analyzed after dedup: 329
- Unfiltered substitution used: False


### Queries Executed
```
rundll32, execution
```

### Retrieval Attempts
| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |
|---:|---|---|---:|---:|---|---:|---|
| 1 | `folder` | Identify all instances of the native Windows process Rundll32 being executed and its associated malicious code. | 10080m | 2000 | `executed` | 371 /  | none |

**Proposed and normalized query details:**

<details><summary>Attempt 1 · folder · executed</summary>

Proposed:
```
rundll32, execution
```
Normalized/executed candidate:
```
rundll32, execution
```
</details>


---

## Evidence and Correlation

### Detection Rule Matches
**15 of 329 analyzed record(s) matched at least one detection rule:**

| Source | Rule ID | Title | Level | Records matched |
|---|---|---|---|---|
| THOS | `thos-0007` | LOLBin Execution via rundll32.exe | medium | 11 |
| Community | `b5de0c9a-6f19-43e0-af4e-55ad01f550af` | Unsigned DLL Loaded by Windows Utility | medium | 10 |
| Community | `e593cf51-88db-4ee1-b920-37e89012a3c9` | Potentially Suspicious Rundll32 Activity | medium | 6 |
| Community | `3a6586ad-127a-4d3b-a677-1e6eacdf8fde` | Windows Shell/Scripting Processes Spawning Suspicious Programs | high | 1 |
| Community | `7cce6fc8-a07f-4d84-a53e-96e1879843c9` | Potential Binary Impersonating Sysinternals Tools | medium | 1 |

### Threat Intelligence Enrichment
Correlated 4 observable indicator(s) against the local blocklist:

| Indicator / IOC | Log Record Index | Source | Threat Metadata |
|---|---|---|---|
| `239.255.255.250` | 189 | `local_blocklist` | {"categories": ["malicious-infrastructure"], "category": "malicious-infrastructure", "confidence": "medium", "first_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "severity": "high", "source_details": {"firehol-level1": {"attribution": "FireHOL blocklist-ipsets", "category": "malicious-infrastructure", "confidence": "medium", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "location": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "name": "FireHOL Level 1", "severity": "high"}}, "source_name": "FireHOL Level 1", "source_url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "sources": ["firehol-level1"], "type": "network"} |
| `239.255.255.250` | 190 | `local_blocklist` | {"categories": ["malicious-infrastructure"], "category": "malicious-infrastructure", "confidence": "medium", "first_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "severity": "high", "source_details": {"firehol-level1": {"attribution": "FireHOL blocklist-ipsets", "category": "malicious-infrastructure", "confidence": "medium", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "location": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "name": "FireHOL Level 1", "severity": "high"}}, "source_name": "FireHOL Level 1", "source_url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "sources": ["firehol-level1"], "type": "network"} |
| `239.255.255.250` | 191 | `local_blocklist` | {"categories": ["malicious-infrastructure"], "category": "malicious-infrastructure", "confidence": "medium", "first_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "severity": "high", "source_details": {"firehol-level1": {"attribution": "FireHOL blocklist-ipsets", "category": "malicious-infrastructure", "confidence": "medium", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "location": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "name": "FireHOL Level 1", "severity": "high"}}, "source_name": "FireHOL Level 1", "source_url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "sources": ["firehol-level1"], "type": "network"} |
| `239.255.255.250` | 199 | `local_blocklist` | {"categories": ["malicious-infrastructure"], "category": "malicious-infrastructure", "confidence": "medium", "first_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "severity": "high", "source_details": {"firehol-level1": {"attribution": "FireHOL blocklist-ipsets", "category": "malicious-infrastructure", "confidence": "medium", "last_seen_by_thos": "2026-07-31T19:30:17.781289+00:00", "location": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "name": "FireHOL Level 1", "severity": "high"}}, "source_name": "FireHOL Level 1", "source_url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "sources": ["firehol-level1"], "type": "network"} |


### Telemetry Coverage Gaps
**ATT&CK technique testability:** `covered` — 1 covered, 0 partial, 0 unavailable of 1 required data source(s).

| Required ATT&CK data source | Status | Confidence | Evidence / gap |
|---|---|---|---|
| Process Creation | `covered` | high | Observed records with event_category: 'process' and event_id matching T1218.011 (rundll32.exe) in the provided samples. The 'folder' telemetry source has multiple records with event_category: 'process' that include specific event IDs (EventID-1, EventID-10) associated with rundll32.exe usage, which is the mechanism for T1218.011. |

**Observed device types:** `{"endpoint": 329}`

**Observed event categories:** `{"process": 329}`


**Coverage gaps and health alerts:**

- No evidence of event_id 4799 being relevant to T1218.011 (this is a different event type for group enumeration)


### Hunt Completeness
- **Status:** `complete`
- **Retrieval branches exhausted:** `True`
- **Selected sources:** `["folder"]`
- **Queried sources:** `["folder"]`
- **Unavailable sources:** `[]`
- **Still capped sources:** `[]`
- **Retrieval attempts:** `1`
- **ATT&CK coverage status:** `covered`

### Representative Evidence
```json
[
  {
    "ref": 254,
    "timestamp": "2019-04-30 07:23:00.914886+00:00",
    "host": "IEWIN7",
    "event": "EventID-10",
    "source_file": "discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx",
    "source_type": "evtx",
    "detail": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Sysmon\" Guid=\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\"></Provider>\n<EventID Qualifiers=\"\">10</EventID>\n<Version>3</Version>\n<Level>4</Level>\n<Task>10</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime=\"2019-04-30 07:23:00.914886+00:00\"></TimeCreated>\n<EventRecordID>8367</EventRecordID>\n<Correlation ActivityID=\"\" RelatedActivityID=\"\"></Correlation>\n<…"
  },
  {
    "ref": 273,
    "timestamp": "2019-05-12 13:30:46.400505+00:00",
    "host": "IEWIN7",
    "event": "EventID-1",
    "source_file": "exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx",
    "source_type": "evtx",
    "detail": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Sysmon\" Guid=\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\"></Provider>\n<EventID Qualifiers=\"\">1</EventID>\n<Version>5</Version>\n<Level>4</Level>\n<Task>1</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime=\"2019-05-12 13:30:46.400505+00:00\"></TimeCreated>\n<EventRecordID>16388</EventRecordID>\n<Correlation ActivityID=\"\" RelatedActivityID=\"\"></Correlation>\n<E…"
  },
  {
    "ref": 0,
    "timestamp": "2023-01-24 11:52:02.155027+00:00",
    "host": "01566s-win16-ir.threebeesco.com",
    "user": "Administrators",
    "event": "EventID-4799",
    "source_file": "4799_remote_local_groups_enumeration.evtx",
    "source_type": "evtx",
    "detail": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\"></Provider>\n<EventID Qualifiers=\"\">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime=\"2023-01-24 11:52:02.155027+00:00\"></TimeCreated>\n<EventRecordID>3819707</EventRecordID>\n<Correlation ActivityID=\"\" RelatedActivityID=…"
  },
  {
    "ref": 5,
    "timestamp": "2019-03-19 23:35:07.524200+00:00",
    "host": "PC01.example.corp",
    "event": "EventID-1102",
    "source_file": "DE_1102_security_log_cleared.evtx",
    "source_type": "evtx",
    "detail": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Eventlog\" Guid=\"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}\"></Provider>\n<EventID Qualifiers=\"\">1102</EventID>\n<Version>0</Version>\n<Level>4</Level>\n<Task>104</Task>\n<Opcode>0</Opcode>\n<Keywords>0x4020000000000000</Keywords>\n<TimeCreated SystemTime=\"2019-03-19 23:35:07.524200+00:00\"></TimeCreated>\n<EventRecordID>452811</EventRecordID>\n<Correlation ActivityID=\"\" RelatedActivityID=\"\"></Correla…"
  },
  {
    "ref": 6,
    "timestamp": "2019-03-19 23:35:08.786015+00:00",
    "host": "PC01.example.corp",
    "event": "EventID-5156",
    "src_ip": "fe80::80ac:4126:fa58:1b81",
    "source_file": "DE_1102_security_log_cleared.evtx",
    "source_type": "evtx",
    "detail": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\"></Provider>\n<EventID Qualifiers=\"\">5156</EventID>\n<Version>1</Version>\n<Level>0</Level>\n<Task>12810</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime=\"2019-03-19 23:35:08.786015+00:00\"></TimeCreated>\n<EventRecordID>452812</EventRecordID>\n<Correlation ActivityID=\"\" RelatedActivityID=\"…"
  }
]
```

---

## Findings
- [hard-evidence] Rundll32.exe was observed executing in the environment (evidence: EventID-10 (rundll32.exe) and EventID-1 (rundll32.exe) in records 254, 273, 274; ref: 254,273,274)

## Recommendations
1. Verify Sysmon configuration for EventID-1 and EventID-10 to ensure rundll32.exe is captured
2. Check for unsigned DLLs in the event logs using the Sigma rule 'Unsigned DLL Loaded by Windows Utility' (rule ID: e593cf51-88db-4ee1-b920-37e89012a3c9)
3. Investigate network connections for the IP 239.255.255.250 (FireHOL Level 1) to confirm malicious infrastructure usage

### Proposed Detection Rule
_No rule proposal generated for this hunt._
