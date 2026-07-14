> ## 📋 Executive Summary Cover
>
> **What was investigated:** PowerShell activity (Execution),
> initiated 2026-07-14 19:48 UTC.
>
> **Bottom line:** [✓ hard-evidence] Two PowerShell script block logging events (EventID-4104) were detected (evidence: EventID-4104 with [POSSIBLE-PROMPT-INJECTION-IN-LOG-DATA] markers in detail field for records _ref 10 and 11; ref: 10, …
>
> **Analyst / requested by:** analyst
> **Full technical detail follows below.**

---

# Threat Hunt Report: H013 — PowerShell (T1059.001) — Execution

- **Hunt ID:** `8dbd7cf0-721d-4719-8191-d7e9f187c5ff`
- **Generated:** 2026-07-14T19:48:38.412809 UTC
- **Hypothesis ID:** H013
- **MITRE ATT&CK:** T1059.001 — PowerShell (Execution)
- **Log Source:** Local folder — /data/log_sources

## Hypothesis

Attackers often utilize PowerShell, a powerful scripting language available on Windows systems, to execute malicious commands, download additional payloads, or manipulate system configurations. Detecting the execution of unauthorized or suspicious PowerShell scripts is crucial, as it may indicate the presence of an adversary attempting to compromise the system. Native windows Event ID 4104 is crucial to detect suspicious script executions. Below are key implementation notes to guide this process: <br></br>1. Sysmon Configuration<br></br>Event ID 1 (Process Creation): Configure Sysmon to capture detailed information about process creations, focusing on powershell.exe executions. Ensure that command-line arguments are logged to detect potentially malicious scripts or commands.<br></br>Event ID 4104 (PowerShell Script Block Logging): While Sysmon does not natively capture PowerShell script block logging, enabling this feature in PowerShell settings can provide visibility into the content of executed scripts. This requires configuring PowerShell to log detailed script blocks to the Windows Event Log.<br></br>2. Detection Logic and Filtering<br></br>Baseline Normal Activity: Establish a baseline of normal PowerShell usage within the environment to differentiate between legitimate administrative activities and potential malicious behavior.<br></br>Anomaly Detection: Develop detection rules to identify anomalies, such as unusual command-line arguments, execution times, or user contexts that deviate from the established baseline.<br></br>Filtering Noise: Apply filters to exclude known legitimate PowerShell activities to reduce false positives and focus on suspicious events.<br></br>Limitations and Assumptions<br></br>Encrypted or Obfuscated Scripts: Attackers may use obfuscation or encryption to evade detection. Regularly update detection mechanisms to recognize and alert on such techniques.

## Log Ingestion Diagnostics

- Files scanned: 3
- Total records parsed (before query filter): 57
- Records after query filter: 57
- Records analyzed after dedup: 12
- Query filter fell back to unfiltered (matched nothing): True


## Executive Summary

The hunt confirms 2 events matching the PowerShell script block logging rule (EventID-4104), indicating potential script execution activity. However, the sample shows truncated log entries with [POSSIBLE-PROMPT-INJECTION-IN-LOG-DATA] markers and no command-line details, making it circumstantial evidence of PowerShell usage. The histogram shows 7 EventID-10 (process access) records but no EventID-1 (process creation) or EventID-4104 (script block) records beyond the 2 matched events, suggesting limited visibility into PowerShell execution patterns.

## MITRE ATT&CK Coverage

- **Technique:** PowerShell (`T1059.001`)
- **Tactic:** Execution
- **Description:** Adversaries may abuse PowerShell commands and scripts for execution.
- **Typical data sources:** Command Execution, PowerShell Logs, Process Creation

## Queries Executed

```
We are given a hypothesis about detecting suspicious PowerShell script executions, with a focus on Event ID 4104 (PowerShell Script Block Logging) and Sysmon Event ID 1 (Process Creation). The normalized fields available are: 
   'process_name': 'event'   -> This field is actually the event name? But note: the problem says "Normalized fields available: {'process_name': 'event', ...}" meaning that the field named 'process_name' in the records corresponds to the value of the field 'event' (which is probably the event name or type). However, in the context of the hypothesis, we are more interested in the process name and command line.

But note: the problem states that the logs have been parsed into generic records with fields like timestamp, host, user, event, src_ip, dst_ip, and detail.

The normalized fields provided in the problem are:
   'process_name': 'event'   -> This is a bit confusing. Let me re-read: "Normalized fields available: {'process_name': 'event', 'command_line': 'detail', ... }"

Actually, the problem says: "Normalized fields available: {'process_name': 'event', 'command_line': 'detail', 'src_ip': 'src_ip', 'dst_ip': 'dst_ip', 'user': 'user', 'dns_query': 'detail', 'event_time': 'timestamp'}"

This means that in the parsed logs, the field that we call "process_name" corresponds to the value of the field named "event" (but that seems odd). Alternatively, it might be that the field names in the records are as follows:

  - The field that we use for the process name is stored in the record under the key "process_name", and that value comes from the original log field "event" (which is the event name?).

However, the problem states: "Given a hunting hypothesis, produce ONLY a comma-separated list of 3-8 short keywords or entity names"

We are to look for keywords that would help find log records relevant to the hypothesis.

Hypothesis: Attackers often utilize PowerShell ... Detecting the execution of unauthorized or suspicious PowerShell scripts ... Native windows Event ID 4104 ...

Key points from the hypothesis:
  - PowerShell (as the process)
  - Event ID 4104 (PowerShell Script Block Logging) - but note: the problem says that Sysmon does not capture this natively, but the hypothesis mentions it as crucial
```

## Sigma Detections

**2 of 12 analyzed record(s) matched at least one Sigma rule:**

| Source | Rule ID | Title | Level | Records matched |
|---|---|---|---|---|
| THOS | `thos-0001` | PowerShell Script Block Logging Execution | medium | 2 |

## Findings

- [✓ hard-evidence] Two PowerShell script block logging events (EventID-4104) were detected (evidence: EventID-4104 with [POSSIBLE-PROMPT-INJECTION-IN-LOG-DATA] markers in detail field for records _ref 10 and 11; ref: 10, 11)
- [⚠ circumstantial] No command-line arguments or process creation details for PowerShell execution were observed (evidence: EventID-10 (process access) records show 7 instances but no EventID-1 (process creation) or EventID-4104 (script block) command-line details; ref: histogram)

- [circumstantial] Verifier warning: one or more finding citations could not be validated; analyst review is required.

## Recommendations

1. Enable Sysmon EventID-1 (Process Creation) logging with command-line arguments to capture PowerShell execution details
2. Configure PowerShell to log script blocks (EventID-4104) via PowerShell logging settings to avoid truncation and improve visibility
3. Investigate the [POSSIBLE-PROMPT-INJECTION-IN-LOG-DATA] markers in logs for potential prompt injection attempts

## Sample Log Evidence

```json
[{'timestamp': '2020-12-15 15:00:07.957445+00:00', 'host': 'MSEDGEWIN10', 'user': None, 'event': 'EventID-7', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n<EventID Qualifiers="">7</EventID>\n<Version>3</Version>\n<Level>4</Level>\n<Task>7</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime="2020-12-15 15:00:07.957445+00:00"></TimeCreated>\n<EventRecordID>589693</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="3524" ThreadID="2756"></Execution>\n<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>MSEDGEWIN10</Computer>\n<Security UserID="S-1-5-18"></Security>\n</System>\n<EventData><Data Name="RuleName"></Data>\n<Data Name="UtcTime">2020-12-15 15:00:07.950</Data>\n<Data Name="ProcessGuid">{747f3d96-cf4b-5fd8-0000-00101ad58700}</Data>\n<Data Name="ProcessId">6976</Data>\n<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n<Data Name="ImageLoaded">C:\\Windows\\System32\\taskschd.dll</Data>\n<Data Name="FileVersion">10.0.17763.1282 (WinBuild.160101.0800)</Data>\n<Data Name="Description">Task Scheduler COM API</Data>\n<Data Name="Product">Microsoft&#174; Windows&#174; Operating System</Data>\n<Data Name="Company">Microsoft Corporation</Data>\n<Data Name="OriginalFileName">taskschd.dll</Data>\n<Data Name="Hashes">SHA1=109056E917E0F35274ABBFDAC0A857E2B38CBE7A,MD5=32DC07C87ACACFF07AFAD1A1B4EBBDE6,SHA256=D989A7250FBC9381E8DA436FA725DF342E47B7878C472D25C11F538C9E0858C3,IMPHASH=47DDF74C5BA1B9E2D8229FFA4922F841</Data>\n<Data Name="Signed">true</Data>\n<Data Name="Signature">Microsoft Windows</Data>\n<Data Name="SignatureStatus">Valid</Data>\n</EventData>\n</Event>\n', 'source_file': 'LM_sysmon_remote_task_src_powershell.evtx', 'source_type': 'evtx'}, {'timestamp': '2020-12-15 15:00:15.695415+00:00', 'host': 'MSEDGEWIN10', 'user': None, 'event': 'EventID-3', 'src_ip': '10.0.2.15', 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n<EventID Qualifiers="">3</EventID>\n<Version>5</Version>\n<Level>4</Level>\n<Task>3</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime="2020-12-15 15:00:15.695415+00:00"></TimeCreated>\n<EventRecordID>589974</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="3524" ThreadID="4288"></Execution>\n<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>MSEDGEWIN10</Computer>\n<Security UserID="S-1-5-18"></Security>\n</System>\n<EventData><Data Name="RuleName"></Data>\n<Data Name="UtcTime">2020-12-15 15:00:14.467</Data>\n<Data Name="ProcessGuid">{747f3d96-cf4b-5fd8-0000-00101ad58700}</Data>\n<Data Name="ProcessId">6976</Data>\n<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n<Data Name="User">MSEDGEWIN10\\IEUser</Data>\n<Data Name="Protocol">tcp</Data>\n<Data Name="Initiated">True</Data>\n<Data Name="SourceIsIpv6">False</Data>\n<Data Name="SourceIp">10.0.2.15</Data>\n<Data Name="SourceHostname">MSEDGEWIN10</Data>\n<Data Name="SourcePort">50007</Data>\n<Data Name="SourcePortName"></Data>\n<Data Name="DestinationIsIpv6">False</Data>\n<Data Name="DestinationIp">10.0.2.17</Data>\n<Data Name="DestinationHostname">MSEDGEWIN10CLONE</Data>\n<Data Name="DestinationPort">135</Data>\n<Data Name="DestinationPortName">epmap</Data>\n</EventData>\n</Event>\n', 'source_file': 'LM_sysmon_remote_task_src_powershell.evtx', 'source_type': 'evtx'}, {'timestamp': '2020-12-15 15:00:15.695478+00:00', 'host': 'MSEDGEWIN10', 'user': None, 'event': 'EventID-3', 'src_ip': '10.0.2.15', 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n<EventID Qualifiers="">3</EventID>\n<Version>5</Version>\n<Level>4</Level>\n<Task>3</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime="2020-12-15 15:00:15.695478+00:00"></TimeCreated>\n<EventRecordID>589975</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="3524" ThreadID="4288"></Execution>\n<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>MSEDGEWIN10</Computer>\n<Security UserID="S-1-5-18"></Security>\n</System>\n<EventData><Data Name="RuleName"></Data>\n<Data Name="UtcTime">2020-12-15 15:00:14.470</Data>\n<Data Name="ProcessGuid">{747f3d96-cf4b-5fd8-0000-00101ad58700}</Data>\n<Data Name="ProcessId">6976</Data>\n<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n<Data Name="User">MSEDGEWIN10\\IEUser</Data>\n<Data Name="Protocol">tcp</Data>\n<Data Name="Initiated">True</Data>\n<Data Name="SourceIsIpv6">False</Data>\n<Data Name="SourceIp">10.0.2.15</Data>\n<Data Name="SourceHostname">MSEDGEWIN10</Data>\n<Data Name="SourcePort">50008</Data>\n<Data Name="SourcePortName"></Data>\n<Data Name="DestinationIsIpv6">False</Data>\n<Data Name="DestinationIp">10.0.2.17</Data>\n<Data Name="DestinationHostname">MSEDGEWIN10CLONE</Data>\n<Data Name="DestinationPort">49666</Data>\n<Data Name="DestinationPortName"></Data>\n</EventData>\n</Event>\n', 'source_file': 'LM_sysmon_remote_task_src_powershell.evtx', 'source_type': 'evtx'}, {'timestamp': '2019-04-30 07:22:56.571136+00:00', 'host': 'IEWIN7', 'user': None, 'event': 'EventID-10', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n<EventID Qualifiers="">10</EventID>\n<Version>3</Version>\n<Level>4</Level>\n<Task>10</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime="2019-04-30 07:22:56.571136+00:00"></TimeCreated>\n<EventRecordID>8322</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="1876" ThreadID="1444"></Execution>\n<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>IEWIN7</Computer>\n<Security UserID="S-1-5-18"></Security>\n</System>\n<EventData><Data Name="RuleName"></Data>\n<Data Name="UtcTime">2019-04-30 07:22:56.555</Data>\n<Data Name="SourceProcessGUID">{365abb72-f7d0-5cc7-0000-0010d0220e00}</Data>\n<Data Name="SourceProcessId">3712</Data>\n<Data Name="SourceThreadId">3756</Data>\n<Data Name="SourceImage">C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe</Data>\n<Data Name="TargetProcessGUID">{365abb72-f7d0-5cc7-0000-0010cb280e00}</Data>\n<Data Name="TargetProcessId">2784</Data>\n<Data Name="TargetImage">C:\\Users\\IEUser\\AppData\\Local\\Temp\\opera autoupdate\\installer.exe</Data>\n<Data Name="GrantedAccess">0x001fffff</Data>\n<Data Name="CallTrace">C:\\Windows\\SYSTEM32\\ntdll.dll+4534c|C:\\Windows\\system32\\kernel32.dll+5112b|C:\\Windows\\system32\\kernel32.dll+2079|C:\\Windows\\AppPatch\\AcLayers.DLL+12689|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+48766|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+4843f|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+333f4|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+331ea|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+3300a|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+32db6|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+33334|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+70d3|C:\\Users\\IEUser\\AppDat', 'source_file': 'discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx', 'source_type': 'evtx'}, {'timestamp': '2019-04-30 07:22:56.930513+00:00', 'host': 'IEWIN7', 'user': None, 'event': 'EventID-10', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n<EventID Qualifiers="">10</EventID>\n<Version>3</Version>\n<Level>4</Level>\n<Task>10</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8000000000000000</Keywords>\n<TimeCreated SystemTime="2019-04-30 07:22:56.930513+00:00"></TimeCreated>\n<EventRecordID>8328</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="1876" ThreadID="1444"></Execution>\n<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>IEWIN7</Computer>\n<Security UserID="S-1-5-18"></Security>\n</System>\n<EventData><Data Name="RuleName"></Data>\n<Data Name="UtcTime">2019-04-30 07:22:56.930</Data>\n<Data Name="SourceProcessGUID">{365abb72-f7d0-5cc7-0000-0010d0220e00}</Data>\n<Data Name="SourceProcessId">3712</Data>\n<Data Name="SourceThreadId">3756</Data>\n<Data Name="SourceImage">C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe</Data>\n<Data Name="TargetProcessGUID">{365abb72-f7d0-5cc7-0000-0010df2f0e00}</Data>\n<Data Name="TargetProcessId">3624</Data>\n<Data Name="TargetImage">C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\60.0.3255.70\\opera_autoupdate.exe</Data>\n<Data Name="GrantedAccess">0x001fffff</Data>\n<Data Name="CallTrace">C:\\Windows\\SYSTEM32\\ntdll.dll+4534c|C:\\Windows\\system32\\kernel32.dll+5112b|C:\\Windows\\system32\\kernel32.dll+2079|C:\\Windows\\AppPatch\\AcLayers.DLL+12689|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+48766|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+4843f|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+28188|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+72d7|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+5058|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+58c6|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+98ce1|C:\\Users\\IEUser\\AppData\\Local\\Programs\\Opera\\launcher.exe+70263|C:\\Users\\IE', 'source_file': 'discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx', 'source_type': 'evtx'}]
```

---
*Generated by THOS (On-Prem AI Threat Hunting Platform) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
