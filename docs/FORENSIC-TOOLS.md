# THOS forensic tools

THOS preserves submitted evidence, verifies its SHA-256 and size before
analysis, and runs only tools selected by the Forensic Planning Agent. Tool
output is treated as evidence; the Forensic Interpretation Agent owns the
evidence-cited assessment. Submitted samples are not executed.

## Installed tools

| Tool | Primary use |
|---|---|
| YARA | File, executable, memory-dump, and process-dump signature matching |
| libmagic `file` | Content-based file identification |
| GNU strings | Bounded ASCII and Unicode string extraction |
| ExifTool | Embedded metadata extraction |
| ClamAV | Known-malware signature screening |
| pefile | Windows PE headers, sections, imports, and structure |
| capa | Static capability identification for PE, ELF, .NET, and shellcode |
| FLOSS | Static, stack, tight, and decoded strings from executables |
| pypdf | PDF metadata, actions, JavaScript, attachments, and structure |
| oletools | Office/OLE macros, objects, and suspicious content |
| Volatility 3 | Agent-selected memory-image plugins |
| libewf tools | E01/Ex01 evidence-container metadata |
| The Sleuth Kit | Disk layout, filesystem metadata, and deleted-file evidence |
| RegRipper | Offline Windows Registry hive parsing |

## Analysis flow

1. Intake stores the original under the managed forensic evidence root and
   records chain-of-custody metadata.
2. Integrity verification recomputes the file size and SHA-256.
3. The Forensic Planning Agent receives artifact facts and the installed tool
   capabilities, then selects an applicable first-pass plan.
4. Tools run read-only with time, output, and file-size limits.
5. The planner can select a second pass from the remaining installed tools.
6. The interpretation stage cites only returned evidence, record, and tool-fact
   identifiers.
7. The report states proven facts, assessments, unresolved anomalies, timeline,
   and recommendations.

## Operations

- Keep the shared ClamAV signature volume current with the `clamav-updater`
  service before relying on ClamAV results.
- Keep capa rules pinned and update the pinned revision through a reviewed image
  build.
- Provide Volatility symbols for the operating-system versions being examined.
- Treat tool errors, unsupported artifact formats, missing symbols, and
  truncated output as explicit examination limitations.
- Never mount submitted evidence into an environment that executes samples.

## Validation

Open **Forensics → Ready forensic tools** and confirm the expected tools are
listed. ClamAV appears only when its signature database is ready. Submit
controlled benign PE, PDF, Office, Registry, memory, and disk
fixtures and confirm that only applicable tools are selected and every reported
fact points to returned tool evidence.
