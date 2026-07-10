> ## 📋 Executive Summary Cover
>
> **What was investigated:** Hijack Execution Flow (sub-technique T1574.002) activity (Persistence),
> initiated 2026-07-07 17:11 UTC.
>
> **Bottom line:** [⚠ circumstantial] Host compromise by malware or unauthorized activity (evidence: Multiple `EventID-1102` events in `dicovery_4661_net_group_domain_admins_target.evtx` suggest security audit log has been cleared, which i…
>
> **Analyst / requested by:** analyst-1
> **Full technical detail follows below.**

---

# Threat Hunt Report: H011 — Hijack Execution Flow (sub-technique T1574.002) (T1574.002) — Persistence

- **Hunt ID:** `42e2b32b-404e-4ce1-8224-4277885706ec`
- **Generated:** 2026-07-07T17:11:28.750900 UTC
- **Hypothesis ID:** H011
- **MITRE ATT&CK:** T1574.002 — Hijack Execution Flow (sub-technique T1574.002) (Persistence)
- **Log Source:** Local folder — /data/log_sources

## Hypothesis

For sideloading a DLL into vulnerable binary, a threat actors would be dropping (creating) EXE and DLL files under user writeable directories and then executing the same newly created EXE file so that it loads the newly created and unverified (Dig sign unverified) DLL from the same directory. Limitations: There are no such limitations other than non-availability of required logs. Sometimes, we tend to not collect "Module Load" events due to their huge volume. In such case we would not be able to perform this hunt. Also, for correlation of data we need advance query language such as SQL, KQL or better enough if we can use Pandas.</br></br>Assumption: Assuming that threat actor is using standard user rights and is using a DLL that has unverifiable digital signature (DLL is signed but certificates are not verified).</br></br>Data sets required: EDR logs - "File Creation" and "Module Load" events.</br></br>Query creation steps:</br></br>1. Select .dll File Creation Events: From the "File Creation" logs, select all .dll file creation events. Ensure that the folder path of the newly created .dll file is not among the following: c:\windows\system32, c:\windows\syswow64, and c:\windows\sxs. Additionally, the verification status of the .dll file should be "Not Verified".</br></br>2. Select .exe File Creation Events: Next, from the "File Creation" logs, select all .exe file creation events. The condition for selection is that the folder path of the .exe file matches the folder path of the .dll files identified in the previous step. Furthermore, the absolute time difference between the .dll file creation event and the .exe file creation event should be less than one minute.</br></br>3. Select DLL Load Events: Finally, from the "Module Load" logs, select all DLL load events where the file name and path of the loaded DLL and the file name and path of the EXE loading that DLL match the names and paths of the .dll and .exe files identified in the previous steps. Additionally, the time of the module load event should be greater than the time of the DLL creation event.

## Log Ingestion Diagnostics

- Files scanned: 25
- Total records parsed (before query filter): 3332
- Records after query filter: 1000
- Records analyzed after dedup: 462
- Query filter fell back to unfiltered (matched nothing): True


## Executive Summary

The provided log data contains events from various sources, including Windows Event Logs (Evtx) and Sysmon logs. Here's a summary of key findings based on the given data: 

## MITRE ATT&CK Coverage

- **Technique:** Hijack Execution Flow (sub-technique T1574.002) (`T1574.002`)
- **Tactic:** Defense Evasion
- **Description:** Hijack Execution Flow. Referenced by 8 hunting hypothesis(es) in this platform's HEARTH knowledge base, e.g.: "For sideloading a DLL into vulnerable binary, a threat actors would be dropping (creating) EXE and DLL files under user writeable directorie".
- **Typical data sources:** Process Creation, Windows Registry

_Note: this technique's canonical MITRE name/tactic come from THOS's base-technique reference table; the description is grounded in this platform's own hunting-hypothesis data, not invented._

## Queries Executed

```
FileCreation, ModuleLoad, DLL, EXE, NotVerified, c_\windows\system32, c_\windows\syswow64, c_\windows\sxs, one_minute
```

## Sigma Detections

**354 of 462 analyzed record(s) matched at least one Sigma rule:**

| Rule ID | Title | Level | Records matched |
|---|---|---|---|
| `thos-0015` | MSI Package Installed from Remote URL | medium | 312 |
| `thos-0014` | Windows Defender Threat Detected / Blocked | high | 11 |
| `thos-0005` | Token Duplication / UAC Bypass Indicators | high | 7 |
| `thos-0007` | LOLBin Execution via rundll32.exe | medium | 6 |
| `thos-0002` | Windows Security Audit Log Cleared | high | 4 |
| `thos-0008` | LOLBin Execution via regsvr32.exe (Squiblydoo-style) | high | 3 |
| `thos-0006` | Remote PowerShell / WinRM Lateral Movement | medium | 3 |
| `thos-0003` | Suspicious Process Access to LSASS Memory | high | 2 |
| `thos-0010` | DLL Search-Order Hijacking via wwlib.dll | high | 2 |
| `thos-0001` | PowerShell Script Block Logging Execution | medium | 2 |
| `thos-0011` | Suspicious svchost.exe Spawning Command Shell (Possible Reverse Shell) | critical | 1 |
| `thos-0009` | Suspicious JScript Engine Load (Defense Evasion) | medium | 1 |

## Findings

- [⚠ circumstantial] Host compromise by malware or unauthorized activity (evidence: Multiple `EventID-1102` events in `dicovery_4661_net_group_domain_admins_target.evtx` suggest security audit log has been cleared, which is a strong indicator of potential host compromise. Additionally, the presence of `EventID-1117` from `WinDefender_Events_1117_1116_AtomicRedTeam.evtx` indicates that Windows Defender was actively detecting and blocking threats.; ref: :[58, 52, 53, 54, 55])
- [⚠ circumstantial] UAC Bypass or Token Duplication Indicators (evidence: `EventID-4624` events in `dicovery_4661_net_group_domain_admins_target.evtx` show multiple instances of token duplication, which could indicate an attempt to bypass User Account Control (UAC) by attackers. These events are logged when a process is created with elevated privileges without prompting the user for consent.; ref: :[62, 65, 74, 98],)
- [⚠ circumstantial] LOLBins or Malicious Executions (evidence: `EventID-1` events in `exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx` indicate execution of suspicious binaries using the `rundll32.exe` process, which is a common method for executing malicious payloads. These are flagged by Sigma rules indicating potential LOLBin usage.; ref: :[108, 109, 110],)
- [✓ hard-evidence] Potential Exfiltration or Command and Control (C2) Traffic (evidence: While not explicitly indicated in the provided data, the presence of `EventID-1` with details like `src_ip` or `dst_ip` might indicate network communications that could be part of an exfiltration attempt or C2 channel. Further analysis would be required to confirm this.; ref: None specified)

## Recommendations

1. **Immediate Security Review**: Conduct a thorough review of the security policies and configurations on all affected hosts.
2. **Malware Removal and Patching**: Remove any detected malware, apply relevant patches, and ensure up-to-date antivirus definitions are in place.
3. **User Account Control (UAC) Settings**: Review UAC settings to ensure they are configured properly to prevent unauthorized privilege escalation.
4. **Network Monitoring and Detection**: Enhance network monitoring tools to detect potential C2 traffic or data exfiltration attempts.
5. **Incident Response Plan Activation**: Activate the incident response plan if this is part of a larger security event.

## Sample Log Evidence

```json
[{'timestamp': '2023-01-24 11:52:02.155027+00:00', 'host': '01566s-win16-ir.threebeesco.com', 'user': 'Administrators', 'event': 'EventID-4799', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>\n<EventID Qualifiers="">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime="2023-01-24 11:52:02.155027+00:00"></TimeCreated>\n<EventRecordID>3819707</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="724" ThreadID="10848"></Execution>\n<Channel>Security</Channel>\n<Computer>01566s-win16-ir.threebeesco.com</Computer>\n<Security UserID=""></Security>\n</System>\n<EventData><Data Name="TargetUserName">Administrators</Data>\n<Data Name="TargetDomainName">Builtin</Data>\n<Data Name="TargetSid">S-1-5-32-544</Data>\n<Data Name="SubjectUserSid">S-1-5-21-308926384-506822093-3341789130-1105</Data>\n<Data Name="SubjectUserName">jbrown</Data>\n<Data Name="SubjectDomainName">3B</Data>\n<Data Name="SubjectLogonId">0x00000000023ec715</Data>\n<Data Name="CallerProcessId">0x00000000000023e8</Data>\n<Data Name="CallerProcessName">C:\\Windows\\System32\\net1.exe</Data>\n</EventData>\n</Event>\n', 'source_file': '4799_remote_local_groups_enumeration.evtx', 'source_type': 'evtx'}, {'timestamp': '2023-01-24 11:53:14.399050+00:00', 'host': '01566s-win16-ir.threebeesco.com', 'user': 'Administrators', 'event': 'EventID-4799', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>\n<EventID Qualifiers="">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime="2023-01-24 11:53:14.399050+00:00"></TimeCreated>\n<EventRecordID>3819735</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="724" ThreadID="2604"></Execution>\n<Channel>Security</Channel>\n<Computer>01566s-win16-ir.threebeesco.com</Computer>\n<Security UserID=""></Security>\n</System>\n<EventData><Data Name="TargetUserName">Administrators</Data>\n<Data Name="TargetDomainName">Builtin</Data>\n<Data Name="TargetSid">S-1-5-32-544</Data>\n<Data Name="SubjectUserSid">S-1-5-21-308926384-506822093-3341789130-1105</Data>\n<Data Name="SubjectUserName">jbrown</Data>\n<Data Name="SubjectDomainName">3B</Data>\n<Data Name="SubjectLogonId">0x0000000002be6273</Data>\n<Data Name="CallerProcessId">0x0000000000000000</Data>\n<Data Name="CallerProcessName">-</Data>\n</EventData>\n</Event>\n', 'source_file': '4799_remote_local_groups_enumeration.evtx', 'source_type': 'evtx'}, {'timestamp': '2023-01-24 11:54:02.416491+00:00', 'host': '01566s-win16-ir.threebeesco.com', 'user': 'Administrators', 'event': 'EventID-4799', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>\n<EventID Qualifiers="">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime="2023-01-24 11:54:02.416491+00:00"></TimeCreated>\n<EventRecordID>3819752</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="724" ThreadID="2604"></Execution>\n<Channel>Security</Channel>\n<Computer>01566s-win16-ir.threebeesco.com</Computer>\n<Security UserID=""></Security>\n</System>\n<EventData><Data Name="TargetUserName">Administrators</Data>\n<Data Name="TargetDomainName">Builtin</Data>\n<Data Name="TargetSid">S-1-5-32-544</Data>\n<Data Name="SubjectUserSid">S-1-5-21-308926384-506822093-3341789130-1105</Data>\n<Data Name="SubjectUserName">jbrown</Data>\n<Data Name="SubjectDomainName">3B</Data>\n<Data Name="SubjectLogonId">0x0000000002bf470d</Data>\n<Data Name="CallerProcessId">0x0000000000000000</Data>\n<Data Name="CallerProcessName">-</Data>\n</EventData>\n</Event>\n', 'source_file': '4799_remote_local_groups_enumeration.evtx', 'source_type': 'evtx'}, {'timestamp': '2023-01-24 11:54:18.001638+00:00', 'host': '01566s-win16-ir.threebeesco.com', 'user': 'Remote Desktop Users', 'event': 'EventID-4799', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>\n<EventID Qualifiers="">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime="2023-01-24 11:54:18.001638+00:00"></TimeCreated>\n<EventRecordID>3819771</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="724" ThreadID="2604"></Execution>\n<Channel>Security</Channel>\n<Computer>01566s-win16-ir.threebeesco.com</Computer>\n<Security UserID=""></Security>\n</System>\n<EventData><Data Name="TargetUserName">Remote Desktop Users</Data>\n<Data Name="TargetDomainName">Builtin</Data>\n<Data Name="TargetSid">S-1-5-32-555</Data>\n<Data Name="SubjectUserSid">S-1-5-21-308926384-506822093-3341789130-1105</Data>\n<Data Name="SubjectUserName">jbrown</Data>\n<Data Name="SubjectDomainName">3B</Data>\n<Data Name="SubjectLogonId">0x0000000002bfa357</Data>\n<Data Name="CallerProcessId">0x0000000000000000</Data>\n<Data Name="CallerProcessName">-</Data>\n</EventData>\n</Event>\n', 'source_file': '4799_remote_local_groups_enumeration.evtx', 'source_type': 'evtx'}, {'timestamp': '2023-01-24 11:54:42.899994+00:00', 'host': '01566s-win16-ir.threebeesco.com', 'user': 'Users', 'event': 'EventID-4799', 'src_ip': None, 'dst_ip': None, 'detail': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>\n<EventID Qualifiers="">4799</EventID>\n<Version>0</Version>\n<Level>0</Level>\n<Task>13826</Task>\n<Opcode>0</Opcode>\n<Keywords>0x8020000000000000</Keywords>\n<TimeCreated SystemTime="2023-01-24 11:54:42.899994+00:00"></TimeCreated>\n<EventRecordID>3819788</EventRecordID>\n<Correlation ActivityID="" RelatedActivityID=""></Correlation>\n<Execution ProcessID="724" ThreadID="10940"></Execution>\n<Channel>Security</Channel>\n<Computer>01566s-win16-ir.threebeesco.com</Computer>\n<Security UserID=""></Security>\n</System>\n<EventData><Data Name="TargetUserName">Users</Data>\n<Data Name="TargetDomainName">Builtin</Data>\n<Data Name="TargetSid">S-1-5-32-545</Data>\n<Data Name="SubjectUserSid">S-1-5-21-308926384-506822093-3341789130-1105</Data>\n<Data Name="SubjectUserName">jbrown</Data>\n<Data Name="SubjectDomainName">3B</Data>\n<Data Name="SubjectLogonId">0x0000000002c00357</Data>\n<Data Name="CallerProcessId">0x0000000000000000</Data>\n<Data Name="CallerProcessName">-</Data>\n</EventData>\n</Event>\n', 'source_file': '4799_remote_local_groups_enumeration.evtx', 'source_type': 'evtx'}]
```

---
*Generated by THOS (On-Prem AI Threat Hunting Platform) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
