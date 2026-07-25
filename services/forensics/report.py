"""Technical, chain-of-custody-aware forensic Markdown reporting."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/data/reports"))


def _table(rows: list[list[object]], headers: list[str]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(value or "").replace("|", "\\|") for value in row) + " |")
    return "\n".join(lines)


def write_forensic_report(verified: dict, triage: dict, correlation: dict, timeline: list[dict]) -> dict:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    case_id = re.sub(r"[^A-Za-z0-9-]", "", str(verified.get("case_id", "case")))[:80]
    filename = f"FORENSIC_{now.strftime('%Y%m%dT%H%M%SZ')}_{case_id}.md"
    path = (REPORTS_DIR / filename).resolve()
    if path.parent != REPORTS_DIR.resolve():
        raise ValueError("invalid forensic report path")
    evidence_rows = [
        [
            item["evidence_id"], item["original_name"], item["size_bytes"],
            f"`{item['sha256']}`", item["extension"], item["magic_hex"],
        ]
        for item in triage["inventory"]
    ]
    sigma_matches = [
        [
            item.get("rule_id"), item.get("title"), item.get("level"),
            item.get("matched_count"),
        ]
        for item in (
            correlation["sigmahq_rule_matches"] + correlation["local_sigma_rule_matches"]
        )[:200]
    ]
    observation_rows = [
        [item["ref"], item.get("event"), item.get("source_file"), item["basis"], item["excerpt"]]
        for item in correlation["suspicious_observations"][:200]
    ]
    timeline_rows = [
        [
            item["timestamp"], item["evidence_ref"], item.get("host"), item.get("user"),
            item.get("event"), item.get("source_file"), item.get("detail"),
        ]
        for item in timeline[:500]
    ]
    archive_summary = [
        {
            "evidence_id": item["evidence_id"],
            "entry_count": len(item["entries"]),
            "entries": item["entries"][:100],
        }
        for item in triage["archives"]
    ]
    report = f"""# Digital Forensic Examination Report — {verified.get('case_title') or case_id}

> **Report classification:** Digital forensic technical report  
> **Case ID:** `{case_id}`  
> **Examiner / analyst:** {verified.get('examiner') or 'Not supplied'}  
> **Evidence received:** {verified.get('received_at') or 'Not recorded'}  
> **Analysis completed:** {now.isoformat()}  
> **Evidence source/tool:** {verified.get('acquired_from') or 'Not supplied'}  
> **Legal authority / authorization:** {verified.get('legal_authority') or 'Not supplied — reviewer must verify before legal use'}

## Executive technical conclusion

THOS verified {len(triage['inventory'])} original evidence file(s) by SHA-256 and analyzed
{correlation['records_analyzed']} normalized artifact/log records. Automated results are
triage leads, not a substitute for examiner validation. No finding below is treated as
proof of attribution or intent without corroborating evidence.

## Scope and examination request

{verified.get('notes') or 'No additional examination notes were supplied.'}

## Chain of custody and integrity

- Original uploads were preserved under `{verified.get('case_dir')}`.
- SHA-256 was calculated during acquisition and independently recomputed before analysis.
- Analysis read the originals; it did not rewrite or normalize the source files.
- The manifest records uploader, received time, original name, stored name, size, media type,
  and acquisition hash.

{_table(evidence_rows, ['Evidence ID', 'Original file', 'Bytes', 'SHA-256', 'Type', 'Magic'])}

## Methodology and tools

1. Validate case containment and chain-of-custody manifest.
2. Recompute full-file SHA-256 and size; stop on any mismatch.
3. Identify artifacts by extension and magic, parse supported log/evidence formats, inventory
   archives without unsafe extraction, and run available disk-image metadata tools.
4. Normalize records using the same schema used for active-SIEM hunting.
5. Evaluate the pinned SigmaHQ and local THOS rules, enumerate indicators, score rare events,
   and construct a timestamp-ordered timeline.
6. Preserve references back to evidence ID and normalized record.

Tooling is local to THOS. Sigma matches, keywords, strings, and anomaly scores are screening
mechanisms and require human validation.

## Evidence-format coverage and limitations

{json.dumps({'warnings': triage['warnings'], 'disk_images': triage['disk_images']}, indent=2, default=str)}

Deep proprietary container interpretation is performed only when an installed, validated
decoder is available. Absence of a decoder is explicitly reported; THOS does not claim that
an opaque container was fully examined.

## Archive/container inventory

```json
{json.dumps(archive_summary, indent=2, default=str)}
```

## Event and artifact profile

```json
{json.dumps(correlation['event_histogram'], indent=2, default=str)}
```

## Indicators observed

```json
{json.dumps(correlation['indicators'], indent=2, default=str)}
```

## Detection correlation

- SigmaHQ rules evaluated: {correlation['sigmahq_rules_evaluated']}
- Local THOS rules evaluated: {correlation['local_sigma_rules_evaluated']}
- Matched record references: {', '.join(correlation['sigma_matched_record_refs'][:500]) or 'None'}

{_table(sigma_matches, ['Rule ID', 'Title', 'Level', 'Matches']) if sigma_matches else '_No Sigma rule matched._'}

## Observations requiring examiner review

{_table(observation_rows, ['Evidence ref', 'Event', 'Source', 'Basis', 'Excerpt']) if observation_rows else '_No review-keyword observations were produced._'}

## Reconstructed timeline

{_table(timeline_rows, ['Timestamp', 'Evidence ref', 'Host', 'User', 'Event', 'Source', 'Detail']) if timeline_rows else '_No parseable timestamps were recovered._'}

## Legal and evidentiary considerations

- Confirm lawful authority, jurisdiction, warrant/consent scope, retention obligations, and
  disclosure rules with counsel or the responsible legal authority.
- Preserve the original media and acquisition documentation separately from this working copy.
- Record every later transfer, examiner action, tool/version change, and derived artifact.
- Reproduce material findings with an independently validated forensic tool before testimony,
  disciplinary action, or other high-impact use.
- Document clock skew, timezone assumptions, encryption, missing decoders, damaged files,
  collection gaps, and any anti-forensic conditions.

## Reviewer sign-off

| Role | Name | Date/time | Decision / notes |
|---|---|---|---|
| Forensic examiner |  |  |  |
| Technical reviewer |  |  |  |
| Legal/case authority (if required) |  |  |  |
"""
    path.write_text(report, encoding="utf-8")
    return {
        "report_path": str(path),
        "report_type": "forensic",
        "summary": (
            f"Verified {len(triage['inventory'])} evidence file(s); analyzed "
            f"{correlation['records_analyzed']} records; produced "
            f"{len(correlation['suspicious_observations'])} review observations."
        ),
    }
