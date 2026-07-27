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


def _proven_facts(verified: dict, triage: dict, correlation: dict, timeline: list[dict]) -> list[str]:
    inventory = triage.get("inventory", [])
    facts = [
        f"{len(inventory)} supplied evidence file(s) passed full-file size and SHA-256 verification against the case manifest.",
        f"{correlation.get('records_analyzed', 0)} normalized record(s) were successfully parsed from the supplied evidence.",
        f"{len(timeline)} record(s) contained a parseable timestamp and were placed in chronological order.",
    ]
    sigma_matches = correlation.get("sigmahq_rule_matches", []) + correlation.get("local_sigma_rule_matches", [])
    if sigma_matches:
        facts.append(
            f"{len(sigma_matches)} configured detection rule(s) matched at least one supplied record; a rule match is evidence of matching conditions, not proof of intent."
        )
    yara_count = int(correlation.get("yara_scan", {}).get("match_count", 0) or 0)
    if yara_count:
        facts.append(f"Enabled YARA rules produced {yara_count} file/artifact match(es) against the verified evidence.")
    ioc_count = len(correlation.get("ioc_matches", []))
    if ioc_count:
        facts.append(f"{ioc_count} observed indicator(s) matched the locally managed intelligence index.")
    if not sigma_matches and not yara_count and not ioc_count:
        facts.append("The configured detection-rule, YARA, and managed-IOC checks produced no deterministic match in the supplied, successfully parsed evidence.")
    return facts


def _unresolved_anomalies(triage: dict, timeline: list[dict]) -> list[str]:
    items = [str(item) for item in triage.get("warnings", []) if str(item).strip()]
    if not timeline:
        items.append("No parseable timestamps were recovered, so event ordering and temporal gaps could not be determined.")
    else:
        items.append("The reconstructed timeline proves only the order of recovered timestamps; missing intervals cannot establish continuous logging.")
    items.append(
        "Whether relevant logs were deleted, overwritten by retention, or removed with anti-forensic tooling cannot be determined unless corroborating journal, sequence, gap, or storage evidence was supplied."
    )
    items.append(
        "Activity outside the supplied sources, collection window, supported decoders, and configured detection/intelligence coverage remains undetermined."
    )
    return list(dict.fromkeys(items))


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
    ioc_rows = [
        [
            item.get("indicator"), item.get("matched_indicator"), item.get("type"),
            item.get("category"), item.get("severity"), item.get("confidence"),
            ", ".join(item.get("sources", [])), item.get("last_seen"),
            ", ".join(item.get("evidence_refs", [])),
        ]
        for item in correlation.get("ioc_matches", [])[:500]
    ]
    observation_rows = [
        [item["ref"], item.get("event"), item.get("source_file"), item["basis"], item["excerpt"]]
        for item in correlation["suspicious_observations"][:200]
    ]
    activity_rows = [
        [
            item.get("classification"), item.get("confidence"), item.get("timestamp"),
            item.get("ref"), item.get("host"), item.get("user"), item.get("event"),
            item.get("source_file"), item.get("basis"), item.get("excerpt"),
        ]
        for item in correlation.get("activity_assessments", [])[:500]
    ]
    timeline_rows = [
        [
            item["timestamp"], item["evidence_ref"], item.get("host"), item.get("user"),
            item.get("event"), item.get("source_file"), item.get("classification"),
            item.get("confidence"), ", ".join(item.get("mitre_techniques", [])),
            item.get("activity_basis"), item.get("detail"),
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
    activities = correlation.get("activity_assessments", [])
    malicious_count = sum(
        1 for item in activities if str(item.get("classification", "")).lower() == "malicious"
    )
    suspicious_count = sum(
        1 for item in activities if str(item.get("classification", "")).lower() == "suspicious"
    )
    sigma_match_count = len(
        correlation.get("sigmahq_rule_matches", [])
        + correlation.get("local_sigma_rule_matches", [])
    )
    yara_match_count = int(correlation.get("yara_scan", {}).get("match_count", 0) or 0)
    ioc_match_count = len(correlation.get("ioc_matches", []))
    proven_facts = _proven_facts(verified, triage, correlation, timeline)
    unresolved_anomalies = _unresolved_anomalies(triage, timeline)
    if malicious_count or suspicious_count:
        conclusion = (
            f"The automated examination identified {malicious_count} malicious and "
            f"{suspicious_count} suspicious activity assessment(s) requiring examiner review "
            "and corroboration."
        )
    else:
        conclusion = (
            "The automated examination did not identify suspicious or malicious activity "
            "through the configured deterministic checks."
        )
    report = f"""# Digital Forensic Examination Report — {verified.get('case_title') or case_id}

> **Report classification:** Digital forensic technical report  
> **Case ID:** `{case_id}`  
> **Examiner / analyst:** {verified.get('examiner') or 'Not supplied'}  
> **Evidence received:** {verified.get('received_at') or 'Not recorded'}  
> **Analysis completed:** {now.isoformat()}  
> **Evidence source/tool:** {verified.get('acquired_from') or 'Not supplied'}  
> **Legal authority / authorization:** {verified.get('legal_authority') or 'Not supplied — reviewer must verify before legal use'}

## Executive summary

THOS verified {len(triage['inventory'])} original evidence file(s) by SHA-256 and analyzed
{correlation['records_analyzed']} normalized artifact/log records and reconstructed
{len(timeline)} timeline entries. The examination produced {sigma_match_count} detection rule
match(es), {yara_match_count} YARA match(es), {ioc_match_count} managed-intelligence IOC
match(es), {malicious_count} malicious assessment(s), and {suspicious_count} suspicious
assessment(s). Automated results are triage leads, not a substitute for examiner validation.
No finding below is treated as proof of attribution or intent without corroborating evidence.

## Scope and examination request

{verified.get('notes') or 'No additional examination notes were supplied.'}

## Proven Facts

The following statements are limited to outcomes directly demonstrated by the verified
evidence and deterministic examination:

{chr(10).join(f'- {item}' for item in proven_facts)}

## Unresolved Anomalies

The examination could not resolve the following gaps or alternative explanations:

{chr(10).join(f'- {item}' for item in unresolved_anomalies)}

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
5. Evaluate the pinned community and local THOS detection rules, scan files with the enabled YARA
   catalog, correlate observed indicators with the managed threat-intelligence index,
   map matched detection knowledge to ATT&CK, score rare events, and construct a
   timestamp-ordered timeline.
6. Preserve references back to evidence ID and normalized record.

Tooling is local to THOS. Detection-rule matches, keywords, strings, and anomaly scores are screening
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

- Community detection rules evaluated: {correlation['sigmahq_rules_evaluated']}
- Local THOS rules evaluated: {correlation['local_sigma_rules_evaluated']}
- Matched record references: {', '.join(correlation['sigma_matched_record_refs'][:500]) or 'None'}
- ATT&CK techniques represented by matched rules: {', '.join(correlation.get('attack_techniques', [])) or 'None mapped'}

{_table(sigma_matches, ['Rule ID', 'Title', 'Level', 'Matches']) if sigma_matches else '_No detection rule matched._'}

## YARA file and artifact correlation

- Files scanned: {correlation.get('yara_scan', {}).get('files_scanned', 0)}
- Files with matches: {correlation.get('yara_scan', {}).get('matched_files', 0)}
- Total YARA matches: {correlation.get('yara_scan', {}).get('match_count', 0)}

```json
{json.dumps(correlation.get('yara_scan', {}), indent=2, default=str)}
```

## Managed threat-intelligence correlation

Observed evidence indicators were compared with the same bounded, locally persisted IOC
index used by hunt enrichment. A match is a triage lead and does not by itself prove malicious
intent; freshness, source provenance, confidence, network role, and surrounding evidence must
be reviewed.

{_table(ioc_rows, ['Observed IOC', 'Matched IOC/network', 'Type', 'Category', 'Severity', 'Confidence', 'Sources', 'Last indexed', 'Evidence refs']) if ioc_rows else '_No observed indicator matched the managed intelligence index._'}

## Suspicious or malicious activity assessment

Classifications are evidence-grounded triage conclusions. A **malicious** classification
requires corroborating deterministic signals; **suspicious** activity requires examiner
review and is not treated as proof of intent or attribution.

{_table(activity_rows, ['Classification', 'Confidence', 'Timestamp', 'Evidence ref', 'Host', 'User', 'Event', 'Source', 'Basis', 'Excerpt']) if activity_rows else '_No suspicious or malicious activity was identified by the configured deterministic checks._'}

## Observations requiring examiner review

{_table(observation_rows, ['Evidence ref', 'Event', 'Source', 'Basis', 'Excerpt']) if observation_rows else '_No review-keyword observations were produced._'}

## Reconstructed timeline

{_table(timeline_rows, ['Timestamp', 'Evidence ref', 'Host', 'User', 'Event', 'Source', 'Classification', 'Confidence', 'MITRE ATT&CK', 'Assessment basis', 'Detail']) if timeline_rows else '_No parseable timestamps were recovered._'}

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

## Final conclusion

{conclusion} This conclusion is limited to the evidence supplied, successfully parsed
formats, configured detection and intelligence knowledge, collection gaps, and documented
tool limitations. Material findings require examiner validation before legal, disciplinary,
containment, or attribution decisions.
"""
    path.write_text(report, encoding="utf-8")
    return {
        "report_path": str(path),
        "report_type": "forensic",
        "summary": (
            f"Verified {len(triage['inventory'])} evidence file(s); analyzed "
            f"{correlation['records_analyzed']} records; produced "
            f"{len(correlation.get('activity_assessments', []))} suspicious/malicious activity assessments."
        ),
    }
