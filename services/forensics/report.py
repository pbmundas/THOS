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
    rule_matches = correlation.get("detection_rule_matches", [])
    if rule_matches:
        facts.append(
            f"{len(rule_matches)} configured detection rule(s) matched at least one supplied record; a rule match is evidence of matching conditions, not proof of intent."
        )
    yara_count = int(correlation.get("yara_scan", {}).get("match_count", 0) or 0)
    if yara_count:
        facts.append(f"Enabled YARA rules produced {yara_count} file/artifact match(es) against the verified evidence.")
    ioc_count = len(correlation.get("ioc_matches", []))
    if ioc_count:
        facts.append(f"{ioc_count} observed indicator(s) matched the locally managed intelligence index.")
    if not rule_matches and not yara_count and not ioc_count:
        facts.append("The configured detection-rule, YARA, and managed-IOC checks produced no deterministic match in the supplied, successfully parsed evidence.")
    static_runs = [
        result
        for artifact in triage.get("static_analysis", [])
        for result in artifact.get("results", [])
        if result.get("status") == "completed"
    ]
    if static_runs:
        facts.append(
            f"{len(static_runs)} routed static-tool invocation(s) completed without executing the supplied artifacts."
        )
    static_findings = sum(
        int(artifact.get("evidence_observation_count", 0) or 0)
        for artifact in triage.get("static_analysis", [])
    )
    if static_findings:
        facts.append(
            f"Selected forensic tools produced {static_findings} additional evidence observation(s); these observations are not automatic verdicts."
        )
    for item in correlation.get("proven_facts", []):
        claim = str(item.get("claim") or "").strip()
        refs = ", ".join(str(value) for value in item.get("evidence_refs") or [])
        if claim and refs:
            facts.append(f"{claim} (evidence: {refs})")
    return facts


def _unresolved_anomalies(
    triage: dict,
    correlation: dict,
    timeline: list[dict],
) -> list[str]:
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
    unavailable = sorted({
        str(result.get("tool_id"))
        for artifact in triage.get("static_analysis", [])
        for result in artifact.get("results", [])
        if result.get("status") in {
            "not_installed", "not_configured", "disabled", "timed_out",
            "skipped_bound", "failed",
        }
    })
    if unavailable:
        items.append(
            "The following applicable static-analysis adapters did not complete and "
            f"therefore cannot support an exclusion: {', '.join(unavailable)}."
        )
    items.extend(
        str(value)
        for value in correlation.get("unresolved_anomalies", [])
        if str(value).strip()
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
    rule_matches = [
        [
            item.get("rule_id"), item.get("title"), item.get("level"),
            item.get("matched_count"),
        ]
        for item in (
            correlation.get("detection_rule_matches", [])
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
    activity_rows = [
        [
            item.get("classification"),
            item.get("confidence"),
            ", ".join(item.get("evidence_refs", [])),
            item.get("claim"),
            item.get("basis"),
            ", ".join(item.get("mitre_techniques", [])),
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
        1
        for item in activities
        if str(item.get("classification", "")).lower()
        in {"confirmed_malicious", "likely_malicious"}
    )
    suspicious_count = sum(
        1 for item in activities if str(item.get("classification", "")).lower() == "suspicious"
    )
    rule_match_count = len(correlation.get("detection_rule_matches", []))
    yara_match_count = int(correlation.get("yara_scan", {}).get("match_count", 0) or 0)
    ioc_match_count = len(correlation.get("ioc_matches", []))
    proven_facts = _proven_facts(verified, triage, correlation, timeline)
    unresolved_anomalies = _unresolved_anomalies(
        triage, correlation, timeline
    )
    static_artifacts = triage.get("static_analysis", [])
    static_tool_rows = [
        [
            artifact.get("evidence_id"),
            result.get("tool_id"),
            result.get("status"),
            result.get("duration_ms"),
            result.get("exit_code"),
            result.get("error") or result.get("note") or "",
        ]
        for artifact in static_artifacts
        for result in artifact.get("results", [])
    ]
    static_finding_count = sum(
        int(artifact.get("evidence_observation_count", 0) or 0)
        for artifact in static_artifacts
    )
    conclusion = str(correlation.get("summary") or "").strip() or (
        "The Forensic Interpretation Agent did not return a validated conclusion."
    )
    disposition = str(
        correlation.get("overall_disposition") or "inconclusive"
    )
    report = f"""# Digital Forensic Examination Report — {verified.get('case_title') or case_id}

> **Report classification:** Digital forensic technical report  
> **Case ID:** `{case_id}`  
> **Examiner / analyst:** {verified.get('examiner') or 'Not supplied'}  
> **Evidence received:** {verified.get('received_at') or 'Not recorded'}  
> **Analysis completed:** {now.isoformat()}  
> **Evidence source/tool:** {verified.get('acquired_from') or 'Not supplied'}  
> **Legal authority / authorization:** {verified.get('legal_authority') or 'Not supplied — reviewer must verify before legal use'}

## Summary

THOS verified {len(triage['inventory'])} original evidence file(s) by SHA-256 and analyzed
{correlation['records_analyzed']} normalized artifact/log records and reconstructed
{len(timeline)} timeline entries. The examination produced {rule_match_count} detection rule
match(es), {yara_match_count} YARA match(es), {ioc_match_count} managed-intelligence IOC
match(es), {static_finding_count} additional static-tool finding(s),
{malicious_count} malicious assessment(s), and {suspicious_count} suspicious
assessment(s). Automated results are triage leads, not a substitute for examiner validation.
No finding below is treated as proof of attribution or intent without corroborating evidence.

**Forensic Interpretation Agent disposition:** `{disposition}`

{conclusion}

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
3. Profile artifacts by content facts and ask the Forensic Planning Agent to select tools
   from the live governed capability catalog.
4. Execute only the planner-selected adapters, then ask the planner whether
   the observed results justify a deeper second pass.
5. Normalize supported records, extract literal observables, correlate those
   observables with the managed threat-intelligence index, and give the
   interpretation agent the cited records and tool facts.
6. Let the interpretation agent assess behavior and map ATT&CK techniques only
   when the supplied evidence supports the mapping.
7. Preserve references back to evidence ID and normalized record.

Tool commands are invoked without a shell, with fixed argument lists, timeouts, and output
limits. Artifacts are not executed. Signatures, metadata, strings, and capabilities
observations are evidence inputs rather than automatic verdicts and require examiner
validation.

## Static forensic tool execution

- Additional deterministic findings: {static_finding_count}

{_table(static_tool_rows, ['Evidence ID', 'Tool', 'Status', 'Duration ms', 'Exit code', 'Limitation / note']) if static_tool_rows else '_No routed static-tool result was recorded._'}

```json
{json.dumps(static_artifacts, indent=2, default=str)}
```

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

- Detection rules evaluated: {correlation.get('detection_rules_evaluated', 0)}
- Matched record references: {', '.join(correlation.get('matched_record_refs', [])[:500]) or 'None'}
- ATT&CK techniques represented by matched rules: {', '.join(correlation.get('attack_techniques', [])) or 'None mapped'}

{_table(rule_matches, ['Rule ID', 'Title', 'Level', 'Matches']) if rule_matches else '_No detection rule matched._'}

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

Classifications below were produced by the Forensic Interpretation Agent and passed
reference validation. Tool or rule matches were supplied as facts, not automatic verdicts.

{_table(activity_rows, ['Classification', 'Confidence', 'Evidence refs', 'Claim', 'Basis', 'MITRE ATT&CK']) if activity_rows else '_No validated activity assessment was returned._'}

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

Disposition: **{disposition}**. {conclusion} This conclusion is limited to the evidence supplied, successfully parsed
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
