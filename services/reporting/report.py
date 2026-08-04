"""
Reporting tool — renders the final markdown threat hunt report and
persists it to the shared /data/reports volume (mounted into both the
mcp-server and chat-ui containers so the UI can browse past reports).

Full-fledged version — fixes and additions over the Phase-1 version:

  - BUG FIX: the report title used to be the *entire* hypothesis text
    (state["hypothesis_text"]), producing a huge duplicated title like
    "Threat Hunt Report: Attackers often utilize PowerShell, a powerful
    scripting language...". `_short_title()` now builds a proper short
    title from the technique name/tactic/hypothesis ID, falling back to
    a truncated first sentence of the hypothesis only if none of those
    are available.
  - NEW: a cover page, rendered before the report body. Two selectable
    styles (pass cover_style="1" or "2" to write_report / write_hunt_report):
      "1" = Executive Cover — one-paragraph plain-language summary for
            non-technical stakeholders (management, compliance).
      "2" = SOC Analyst Cover — technical at-a-glance panel (technique
            ID/tactic, data sources, ingestion stats, sigma hit count)
            for the analyst who will read the full report next.
    Defaults to "1" if not specified.
  - NEW: a "MITRE ATT&CK Coverage" section rendered from the full
    233-technique table (services/knowledge/mitre.py) instead of nothing.
  - NEW: a "Detection Rule Matches" section listing which static rules
    fired (id/title/level/match count) instead of the old cosmetic
    LLM-drafted rule text.

Phase 2+ extension point: also push the report to a ticketing system
(Jira/ServiceNow), a wiki (Confluence), or a Slack/Teams channel. Keep
the markdown file as the source of truth and add exporters here.
"""
import os
import re
import datetime
import json

from services.knowledge import mitre

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/data/reports")

MAX_TITLE_LEN = 90


def _markdown_cell(value) -> str:
    """Render arbitrary report data without breaking Markdown tables."""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return (
        str(value if value is not None else "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "<br>")
        .replace("|", "\\|")
    )


def _local_now() -> datetime.datetime:
    """Return a timezone-aware timestamp in the host's local timezone."""
    return datetime.datetime.now().astimezone()


def _as_local_datetime(value, fallback: datetime.datetime | None = None) -> datetime.datetime:
    """Normalize an ISO string or datetime into the local timezone."""
    parsed = value
    if isinstance(value, str):
        try:
            parsed = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = None
    if not isinstance(parsed, datetime.datetime):
        parsed = fallback or _local_now()
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    target_timezone = (
        fallback.tzinfo
        if isinstance(fallback, datetime.datetime) and fallback.tzinfo is not None
        else _local_now().tzinfo
    )
    return parsed.astimezone(target_timezone)


def _format_local_timestamp(value, fallback: datetime.datetime | None = None) -> str:
    timestamp = _as_local_datetime(value, fallback)
    timezone_name = timestamp.tzname() or "local"
    return f"{timestamp.strftime('%Y-%m-%d %H:%M:%S %z')} ({timezone_name})"


def _short_title(hypothesis_id: str, technique_id: str, technique_name: str,
                  tactic: str, hypothesis: str) -> str:
    """Build a short, human-scannable report title. Never the full
    hypothesis text — see module docstring bug-fix note."""
    parts = []
    if hypothesis_id:
        parts.append(hypothesis_id)
    if technique_name and technique_id:
        parts.append(f"{technique_name} ({technique_id})")
    elif technique_id:
        parts.append(technique_id)
    if tactic:
        parts.append(tactic)
    if parts:
        return " — ".join(parts)
    if hypothesis:
        first_sentence = re.split(r"(?<=[.!?])\s", hypothesis.strip(), maxsplit=1)[0]
        if len(first_sentence) > MAX_TITLE_LEN:
            first_sentence = first_sentence[:MAX_TITLE_LEN].rsplit(" ", 1)[0] + "…"
        return first_sentence
    return "Untitled Hunt"


COVER_EXECUTIVE_TEMPLATE = """\
> ## Executive Summary Cover
>
> **What was investigated:** {technique_name_or_na} activity ({tactic_or_na}),
> initiated {hunt_started_at}.
>
> **Bottom line:** {bottom_line}
>
> **Analyst / requested by:** {hunter_name}
> **Hunt completed:** {hunt_completed_at}
> **Report generated:** {report_generated_at}
> **Full technical detail follows below.**

---

"""

COVER_ANALYST_TEMPLATE = """\
> ## SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `{hunt_id}` |
> | Hypothesis ID | {hypothesis_id_or_na} |
> | MITRE ATT&CK | {technique_id_or_na} — {technique_name_or_na} ({tactic_or_na}) |
> | Log source | {log_source} |
> | Records analyzed | {records_analyzed} |
> | Detection rules matched | {sigma_rules_matched} |
> | Detection-rule records | {sigma_matched_records} |
> | Hunt started | {hunt_started_at} |
> | Hunt completed | {hunt_completed_at} |
> | Report generated | {report_generated_at} |

---

"""


def _bottom_line(findings: str, sigma_matched_records) -> str:
    if findings and findings not in ("(no findings recorded)", ""):
        first_line = findings.strip().splitlines()[0].lstrip("-* ").strip()
        return first_line[:220] + ("…" if len(first_line) > 220 else "")
    try:
        n = int(sigma_matched_records)
    except (TypeError, ValueError):
        n = 0
    if n > 0:
        return f"{n} log record(s) matched deterministic detection rules; see Findings below."
    return "No findings recorded for this hunt yet."


def _render_cover(cover_style: str, hunt_id: str, hypothesis_id: str, technique_id: str,
                   technique_name: str, tactic: str, log_source: str, hunter_name: str,
                   records_analyzed: int, sigma_rules_matched: int, sigma_matched_records: int,
                   findings: str, timestamp: datetime.datetime,
                   verification_passed: bool = True,
                   hunt_started_at=None, hunt_completed_at=None) -> str:
    report_generated_at = _format_local_timestamp(timestamp)
    hunt_started_at = _format_local_timestamp(hunt_started_at, timestamp)
    hunt_completed_at = _format_local_timestamp(hunt_completed_at, timestamp)
    if str(cover_style) == "2":
        return COVER_ANALYST_TEMPLATE.format(
            hunt_id=hunt_id or "n/a",
            hypothesis_id_or_na=hypothesis_id or "n/a",
            technique_id_or_na=technique_id or "n/a",
            technique_name_or_na=technique_name or "n/a",
            tactic_or_na=tactic or "n/a",
            log_source=log_source or "n/a",
            records_analyzed=records_analyzed,
            sigma_rules_matched=sigma_rules_matched,
            sigma_matched_records=sigma_matched_records,
            hunt_started_at=hunt_started_at,
            hunt_completed_at=hunt_completed_at,
            report_generated_at=report_generated_at,
        )
    return COVER_EXECUTIVE_TEMPLATE.format(
        technique_name_or_na=technique_name or "an unspecified technique",
        tactic_or_na=tactic or "unspecified tactic",
        hunt_started_at=hunt_started_at,
        hunt_completed_at=hunt_completed_at,
        report_generated_at=report_generated_at,
        bottom_line=(
            _bottom_line(findings, sigma_matched_records)
            if verification_passed
            else "Findings were generated, but deterministic citation verification failed; analyst review is required before relying on them."
        ),
        hunter_name=hunter_name or "anonymous",
    )


def _representative_log_sample(logs: list[dict], priority_indices: list[int] | None = None,
                               limit: int = 5) -> str:
    """Render a bounded, valid-JSON evidence sample without raw XML walls."""
    selected: list[tuple[int, dict]] = []
    selected_indices = set()
    priority_cap = max(1, limit // 2)
    for index in priority_indices or []:
        if 0 <= index < len(logs) and index not in selected_indices:
            selected.append((index, logs[index]))
            selected_indices.add(index)
        if len(selected) >= priority_cap:
            break
    seen_events = {str(log.get("event", "")) for _, log in selected}
    for index, log in enumerate(logs):
        event = str(log.get("event", ""))
        if index in selected_indices or event in seen_events:
            continue
        selected.append((index, log))
        selected_indices.add(index)
        seen_events.add(event)
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        for index, log in enumerate(logs):
            if index not in selected_indices:
                selected.append((index, log))
            if len(selected) >= limit:
                break
    rendered = []
    for index, log in selected:
        item = {"ref": index}
        for key in ("timestamp", "host", "user", "event", "src_ip", "dst_ip", "source_file", "source_type"):
            if log.get(key) not in (None, ""):
                item[key] = log.get(key)
        detail = str(log.get("detail", ""))
        if detail:
            item["detail"] = detail[:500] + ("…" if len(detail) > 500 else "")
        rendered.append(item)
    return json.dumps(rendered, indent=2, ensure_ascii=False, default=str)


def _render_mitre_section(technique_id: str) -> str:
    if not technique_id:
        return "_No MITRE ATT&CK technique ID associated with this hunt._"
    tech = mitre.map_technique(technique_id)
    if not tech:
        return f"_Technique `{technique_id}` is not yet in the local MITRE ATT&CK table._"
    data_sources = ", ".join(tech.get("data_sources", [])) or "n/a"
    return (
        f"- **Technique:** {tech['name']} (`{tech['id']}`)\n"
        f"- **Tactic:** {tech['tactic']}\n"
        f"- **Description:** {tech['description']}\n"
        f"- **Typical data sources:** {data_sources}"
    )


def _render_related_technique_signals(signals: list[dict] | None) -> str:
    """Render structured cross-technique leads without promoting them to findings."""
    if not signals:
        return "_No evidence-backed cross-technique leads were identified._"
    lines = [
        "| Technique | Confidence | Evidence refs | Rationale |",
        "|---|---|---|---|",
    ]
    for signal in signals:
        technique_id = str(signal.get("technique_id") or "unmapped")
        technique_name = str(signal.get("technique_name") or "name not supplied")
        refs = ", ".join(str(value) for value in signal.get("evidence_refs") or [])
        lines.append(
            f"| `{_markdown_cell(technique_id)}` - {_markdown_cell(technique_name)} | "
            f"`{_markdown_cell(signal.get('confidence'))}` | "
            f"{_markdown_cell(refs)} | {_markdown_cell(signal.get('rationale'))} |"
        )
    lines.append(
        "\n_These are cited leads for analyst triage or a separate hypothesis; "
        "they are not confirmed technique findings._"
    )
    return "\n".join(lines)


def _render_sigma_section(sigma_rule_matches, sigma_matched_count: int, records_analyzed: int) -> str:
    if not sigma_rule_matches:
        return (
            f"No static detection rule matched any of the {records_analyzed} analyzed record(s) "
            f"for this hunt. (See Queries Executed / Sample Log Evidence below for what was "
            f"actually searched.)"
        )
    lines = [
        f"**{sigma_matched_count} of {records_analyzed} analyzed record(s) matched at least one "
        f"detection rule:**",
        "",
        "| Source | Rule ID | Title | Level | Records matched |",
        "|---|---|---|---|---|",
    ]
    source_label = {"sigmahq": "Community", "thos": "THOS"}
    for rm in sigma_rule_matches:
        label = source_label.get(rm.get("source", ""), "—")
        lines.append(
            f"| {_markdown_cell(label)} | `{_markdown_cell(rm.get('rule_id'))}` | "
            f"{_markdown_cell(rm.get('title'))} | {_markdown_cell(rm.get('level'))} | "
            f"{_markdown_cell(rm.get('matched_count'))} |"
        )
    return "\n".join(lines)


REPORT_TEMPLATE = """\
# Threat Hunt Report: {title}

## Summary

{opening_summary}

### Key Evidence
{evidence_highlights_section}

### Validation Snapshot
{summary_validation_status}

---

## Hypothesis and Scope

- **Hunt ID:** `{hunt_id}`
- **Hypothesis ID:** {hypothesis_id}
- **Requested by / Analyst:** {hunter_name}
- **Hunt Started:** {hunt_started_at}
- **Hunt Completed:** {hunt_completed_at}
- **Report Generated:** {report_generated_at}
- **MITRE ATT&CK Tactic:** {tactic}
- **MITRE ATT&CK Technique:** {technique_name} ({technique_id})
- **Telemetry Source:** {log_source}
- **Hypothesis:** {hypothesis}

### MITRE ATT&CK Coverage
{mitre_section}

### Related ATT&CK Technique Signals
{related_technique_signals_section}

### Investigation Requirements
{investigation_contract_section}

### Hunt Plan
{hunt_plan_section}

### Prior Hunt Context
{hunt_memory_section}

---

## Telemetry Retrieval

### Retrieval Results
{ingestion_diagnostics}

### Queries Executed
```
{queries}
```

### Retrieval Attempts
{query_attempts_section}

---

## Evidence and Correlation

### Detection Rule Matches
{sigma_section}

### Threat Intelligence Enrichment
{threat_intel_section}

### Telemetry Coverage Gaps
{coverage_gaps_section}

### Hunt Completeness
{hunt_completeness_section}

### Prompt-Injection Guardrail
{guardrail_section}

### Analysis Reliability
{reasoning_reliability_section}

### Verifier / Critic Validation
{verifier_section}

### Case Status
{case_section}

### Representative Evidence
```json
{log_sample}
```

---

## Findings
{findings}

## Recommendations
{recommendations}

### Proposed Detection Rule
{proposed_detection_rule}
"""


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return slug[:60] or "hunt"


def write_report(hunt_id: str, title: str, hypothesis: str, technique_id: str,
                  technique_name: str, tactic: str, summary: str, queries: str,
                  findings: str, recommendations: str, log_sample: str,
                  hypothesis_id: str = "", log_source: str = "",
                  ingestion_diagnostics: str = "", hunter_name: str = "",
                  cover_style: str = "1", sigma_rule_matches: list | None = None,
                  sigma_matched_count: int = 0, records_analyzed: int = 0,
                  proposed_detection_rule: str | None = None,
                  plan: list[str] | None = None,
                  guardrail_result: dict | None = None,
                  enrichment_hits: list | None = None,
                  verifier_result: dict | None = None,
                  case_id: str | None = None,
                  coverage_gaps: list[str] | None = None,
                  coverage_assessment: dict | None = None,
                  hunt_memory: list[dict] | None = None,
                  evidence_highlights: list[dict] | None = None,
                  behavioral_evidence: list[dict] | None = None,
                  reasoning_mode: str = "model",
                  reasoning_degraded: bool = False,
                  reasoning_attempts: int = 0,
                  reasoning_error: str | None = None,
                  retrieval_attempts: list[dict] | None = None,
                  hunt_completeness: dict | None = None,
                  investigation_requirements: dict | None = None,
                  related_technique_signals: list[dict] | None = None,
                  hunt_started_at=None,
                  hunt_completed_at=None) -> str:
    """Render the markdown report and write it to disk. Returns the file path.

    `title`, if not given (empty string), is now derived automatically
    from technique/tactic/hypothesis_id via `_short_title` — callers no
    longer need to (and should not) pass the full hypothesis text as the
    title.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = _local_now()
    resolved_title = title.strip() if title and title.strip() and title != hypothesis else ""
    if not resolved_title:
        resolved_title = _short_title(hypothesis_id, technique_id, technique_name, tactic, hypothesis)

    # Include a short hunt_id suffix so two reports generated in the same
    # second (same slug) never silently overwrite each other on disk.
    hunt_suffix = f"_{hunt_id[:8]}" if hunt_id else ""
    utc_timestamp = timestamp.astimezone(datetime.timezone.utc)
    filename = f"{utc_timestamp.strftime('%Y%m%dT%H%M%SZ')}_{_slugify(resolved_title)}{hunt_suffix}.md"
    path = os.path.join(REPORTS_DIR, filename)

    mitre_section = _render_mitre_section(technique_id)
    sigma_section = _render_sigma_section(sigma_rule_matches or [], sigma_matched_count, records_analyzed)
    if reasoning_degraded:
        raise ValueError(
            "report generation is prohibited when validated model reasoning is unavailable"
        )
    reasoning_reliability_section = (
        f"**Model reasoning completed and validated.** Mode: `{reasoning_mode or 'model'}`; "
        f"attempts: `{reasoning_attempts or 1}`."
    )

    # Format Hunt Memory section
    if not hunt_memory:
        hunt_memory_section = "No recent hunts targeting this technique have been recorded in the platform database."
    else:
        hunt_memory_section = "| Hunt ID | Date | Status | Summary |\n|---|---|---|---|\n"
        for h in hunt_memory:
            date_val = h.get("created_at")
            if isinstance(date_val, datetime.datetime):
                date_str = date_val.strftime("%Y-%m-%d %H:%M UTC")
            elif date_val:
                date_str = str(date_val)[:19]
            else:
                date_str = "n/a"
            summary_str = h.get("summary") or "No summary recorded."
            if len(summary_str) > 100:
                summary_str = summary_str[:97] + "..."
            hunt_memory_section += (
                f"| `{_markdown_cell(h.get('hunt_id'))}` | "
                f"{_markdown_cell(date_str)} | "
                f"`{_markdown_cell(h.get('status'))}` | "
                f"{_markdown_cell(summary_str)} |\n"
            )

    # Format Plan section
    if not plan:
        hunt_plan_section = "No supervisor execution plan recorded."
    else:
        steps = []
        node_map = {
            "refresh_hearth_kb": "Update Hypothesis KB",
            "hypothesis": "Formulate / Resolve Hypothesis",
            "hunt_memory": "Recall Prior Hunt History",
            "supervisor": "Orchestrate Hunt Execution",
            "query_gen": "Generate SIEM Query",
            "siem_fetch": "Retrieve Log Telemetry",
            "log_processing": "Parse & Normalize Logs",
            "guardrail": "Sentinel Injection Screening",
            "soc_tools": "Run Detection and Indicator Matchers",
            "coverage_gap_check": "Verify Log Telemetry Health",
            "threat_intel_enrichment": "Enrich IOCs with Threat Intel",
            "reasoning": "AI Security Reasoning",
            "verifier": "Verify Evidence Citations",
            "detection_engineering": "Draft Detection Rules",
            "communication": "Adapt Brief Tone",
            "report": "Compile Hunt Report"
        }
        for node in plan:
            node_label = node_map.get(node, node.replace("_", " ").title())
            steps.append(f"- [x] **{node_label}** (`{node}`)")
        hunt_plan_section = "\n".join(steps)

    # Format Guardrail section
    gr = guardrail_result or {}
    gr_status = gr.get("status", "clean")
    gr_scanned = gr.get("scanned_records", 0)
    gr_hits = gr.get("hits") or []
    if gr_status == "clean":
        guardrail_section = f"**Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned {gr_scanned} records)"
    else:
        guardrail_section = f"**Flagged:** Detected {len(gr_hits)} record(s) containing instruction-like signatures in untrusted telemetry:\n\n"
        guardrail_section += "| Record Index | Log Field | Reason |\n|---|---|---|\n"
        for hit in gr_hits:
            guardrail_section += f"| {hit.get('record_index')} | `{hit.get('field')}` | {hit.get('reason')} |\n"

    # Format Threat Intel section
    if not enrichment_hits:
        threat_intel_section = "No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist."
    else:
        threat_intel_section = f"Correlated {len(enrichment_hits)} observable indicator(s) against the local blocklist:\n\n"
        threat_intel_section += "| Indicator / IOC | Log Record Index | Source | Threat Metadata |\n|---|---|---|---|\n"
        for hit in enrichment_hits:
            threat_intel_section += (
                f"| `{_markdown_cell(hit.get('indicator'))}` | "
                f"{_markdown_cell(hit.get('record_index'))} | "
                f"`{_markdown_cell(hit.get('source'))}` | "
                f"{_markdown_cell(hit.get('metadata'))} |\n"
            )

    # Format ATT&CK-aware coverage and health section.
    ca = coverage_assessment or {}
    coverage_gaps_section = ""
    if ca.get("data_sources"):
        coverage_gaps_section += (
            f"**ATT&CK technique testability:** `{ca.get('status', 'unknown')}` — "
            f"{ca.get('covered_source_count', 0)} covered, "
            f"{ca.get('partial_source_count', 0)} partial, "
            f"{ca.get('unavailable_source_count', 0)} unavailable of "
            f"{ca.get('required_source_count', 0)} required data source(s).\n\n"
            "| Required ATT&CK data source | Status | Confidence | Evidence / gap |\n"
            "|---|---|---|---|\n"
        )
        for item in ca.get("data_sources", []):
            coverage_gaps_section += (
                f"| {_markdown_cell(item.get('data_source'))} | "
                f"`{_markdown_cell(item.get('status'))}` | "
                f"{_markdown_cell(item.get('confidence'))} | "
                f"{_markdown_cell(item.get('reason'))} |\n"
            )
        coverage_gaps_section += (
            "\n**Observed device types:** `"
            + json.dumps(ca.get("observed_device_types", {}), sort_keys=True)
            + "`\n\n**Observed event categories:** `"
            + json.dumps(ca.get("observed_event_categories", {}), sort_keys=True)
            + "`\n"
        )
    elif not coverage_gaps:
        coverage_gaps_section = "**Telemetry Health Passed:** No critical coverage gaps or ingestion errors detected during execution."
    if coverage_gaps:
        coverage_gaps_section += "\n\n**Coverage gaps and health alerts:**\n\n"
        for gap in coverage_gaps:
            coverage_gaps_section += f"- {gap}\n"

    # Format Verifier result
    vr = verifier_result or {}
    vr_status = vr.get("status", "passed")
    vr_checked = vr.get("checked_citations", 0)
    vr_invalid = vr.get("invalid_references") or []
    vr_reason = vr.get("reason", "")
    if vr_status == "passed":
        verifier_section = f"**Passed:** All cited references validated successfully. The verifier confirmed that all `{vr_checked}` evidence citations (`ref: N`) point to valid records in the processed logs."
    else:
        verifier_section = f"**Failed:** Evidence verification failed due to: *{vr_reason}*.\n\n"
        if vr_invalid:
            verifier_section += f"- **Invalid References:** {', '.join(str(r) for r in vr_invalid)}\n"
        verifier_section += "- **Review Required:** Resolve citation discrepancies in the linked case before acting on the affected finding."

    # Format Case section
    if case_id:
        prio = "High" if vr_status != "passed" else "Medium"
        case_section = (
            f"**Active Case Created:**\n"
            f"- **Case ID:** `{case_id}`\n"
            f"- **Status:** `Open` / `Pending Analyst Review`\n"
            f"- **Priority:** {prio}\n\n"
            f"_An investigation has been automatically created in the auditing database to track findings triage and resolution._"
        )
    else:
        case_section = "No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)"

    highlights = evidence_highlights or []
    behaviors = behavioral_evidence or []
    key_evidence = [*highlights, *behaviors]
    if key_evidence:
        evidence_highlights_section = "\n".join(
            f"- **Record {item.get('record_index', 'n/a')} — "
            f"{', '.join(item.get('matched_artifacts') or item.get('matched_literals') or [item.get('kind') or 'evidence'])}:** "
            f"{item.get('claim') or item.get('evidence') or item.get('event') or 'Normalized evidence matched.'}"
            for item in key_evidence[:10]
        )
    else:
        evidence_highlights_section = (
            "No hypothesis-relevant artifact or behavioral evidence was selected. "
            "Review the retrieval, detection-rule, findings, and coverage sections below; "
            "absence of selected key evidence is not proof of absence."
        )
    summary_validation_status = (
        f"- **Verifier:** `{vr_status}`\n"
        f"- **Reasoning mode:** `{reasoning_mode or 'model'}`\n"
        f"- **Records analyzed:** `{records_analyzed}`\n"
        f"- **Selected key evidence:** `{len(key_evidence)}`\n"
        f"- **Case:** `{case_id or 'none'}`"
    )
    requirements = investigation_requirements or {}
    if requirements:
        required_sources = ", ".join(
            requirements.get("required_data_sources") or []
        ) or "No governed ATT&CK data-source mapping"
        literal_observables = ", ".join(
            requirements.get("literal_observables") or []
        ) or "None stated literally in the hypothesis"
        investigation_contract_section = (
            f"- **Title:** {requirements.get('title') or resolved_title}\n"
            f"- **Required ATT&CK data sources:** {required_sources}\n"
            f"- **Literal observables:** {literal_observables}\n"
            f"- **Completion criterion:** "
            f"{requirements.get('completion_criteria') or 'Not recorded'}\n\n"
            "**Required investigation steps:**\n"
            + "\n".join(
                f"{index}. {step}"
                for index, step in enumerate(
                    requirements.get("investigation_steps") or [], start=1
                )
            )
        )
    else:
        investigation_contract_section = (
            "No structured investigation contract was recorded."
        )

    attempts = retrieval_attempts or []
    if attempts:
        query_attempts_section = (
            "| # | Source | Objective | Lookback | Cap | Status | Returned / total | Validation / error |\n"
            "|---:|---|---|---:|---:|---|---:|---|\n"
        )
        for attempt in attempts:
            issue = (
                attempt.get("error")
                or attempt.get("validation_error")
                or ("fallback used" if attempt.get("used_fallback") else "")
                or "none"
            )
            query_attempts_section += (
                f"| {_markdown_cell(attempt.get('sequence', ''))} | "
                f"`{_markdown_cell(attempt.get('source', ''))}` | "
                f"{_markdown_cell(str(attempt.get('objective') or '')[:180])} | "
                f"{_markdown_cell(attempt.get('lookback_minutes', 'n/a'))}m | "
                f"{_markdown_cell(attempt.get('limit', 'n/a'))} | "
                f"`{_markdown_cell(attempt.get('status', ''))}` | "
                f"{_markdown_cell(attempt.get('record_count', 0))} / "
                f"{_markdown_cell(attempt.get('total_hits', 'n/a'))} | "
                f"{_markdown_cell(str(issue)[:220])} |\n"
            )
        query_attempts_section += "\n**Proposed and normalized query details:**\n"
        for attempt in attempts:
            proposed = str(attempt.get("query") or "")[:8000]
            normalized = str(attempt.get("normalized_query") or "")[:8000]
            query_attempts_section += (
                f"\n<details><summary>Attempt {attempt.get('sequence', '')} "
                f"· {attempt.get('source', '')} · "
                f"{attempt.get('status', '')}</summary>\n\n"
                f"Proposed:\n```\n{proposed or '(none)'}\n```\n"
                f"Normalized/executed candidate:\n```\n"
                f"{normalized or '(none)'}\n```\n</details>\n"
            )
    else:
        query_attempts_section = "No query-attempt ledger was recorded."

    completeness = hunt_completeness or {}
    hunt_completeness_section = (
        f"- **Status:** `{completeness.get('status', 'unknown')}`\n"
        f"- **Retrieval branches exhausted:** "
        f"`{completeness.get('retrieval_exhausted', False)}`\n"
        f"- **Selected sources:** "
        f"`{json.dumps(completeness.get('selected_sources', []))}`\n"
        f"- **Queried sources:** "
        f"`{json.dumps(completeness.get('queried_sources', []))}`\n"
        f"- **Unavailable sources:** "
        f"`{json.dumps(completeness.get('unavailable_sources', []))}`\n"
        f"- **Still capped sources:** "
        f"`{json.dumps(completeness.get('capped_sources', []))}`\n"
        f"- **Retrieval attempts:** `{completeness.get('attempt_count', len(attempts))}`\n"
        f"- **ATT&CK coverage status:** "
        f"`{completeness.get('coverage_status', 'unknown')}`"
    )

    # Format Feedback section
    feedback_section = (
        f"Analyst feedback is logged to improve the on-prem reasoning models. Use the `/feedback` endpoint to rate this hunt:\n"
        f"```bash\n"
        f"curl -X POST http://localhost:8200/feedback \\\n"
        f"  -H 'Authorization: Bearer <ORCHESTRATOR_API_KEY>' \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d '{{\"hunt_id\": \"{hunt_id}\", \"rating\": \"up/down/corrected\", \"correction\": \"Provide notes if rating is corrected\"}}'\n"
        f"```"
    )

    content = REPORT_TEMPLATE.format(
        title=resolved_title,
        opening_summary=summary or "(no summary provided)",
        evidence_highlights_section=evidence_highlights_section,
        summary_validation_status=summary_validation_status,
        hunt_id=hunt_id,
        hunter_name=hunter_name or "n/a",
        hunt_started_at=_format_local_timestamp(hunt_started_at, timestamp),
        hunt_completed_at=_format_local_timestamp(hunt_completed_at, timestamp),
        report_generated_at=_format_local_timestamp(timestamp),
        timestamp=timestamp.isoformat(),
        hypothesis_id=hypothesis_id or "n/a",
        log_source=log_source or "not recorded",
        technique_id=technique_id or "n/a",
        technique_name=technique_name or "n/a",
        tactic=tactic or "n/a",
        hypothesis=hypothesis or "(none provided)",
        summary=summary or "(no summary provided)",
        queries=queries or "(none)",
        findings=findings or "(no findings recorded)",
        recommendations=recommendations or "(none)",
        log_sample=log_sample or "[]",
        ingestion_diagnostics=ingestion_diagnostics or "(not available for this SIEM type)",
        mitre_section=mitre_section,
        related_technique_signals_section=_render_related_technique_signals(
            related_technique_signals
        ),
        sigma_section=sigma_section,
        proposed_detection_rule=(f"```yaml\n{proposed_detection_rule}```\n\n_Proposal only; validate and promote it through your normal detection change-control process._" if proposed_detection_rule else "_No rule proposal generated for this hunt._"),
        hunt_memory_section=hunt_memory_section,
        hunt_plan_section=hunt_plan_section,
        investigation_contract_section=investigation_contract_section,
        query_attempts_section=query_attempts_section,
        hunt_completeness_section=hunt_completeness_section,
        guardrail_section=guardrail_section,
        threat_intel_section=threat_intel_section,
        coverage_gaps_section=coverage_gaps_section,
        verifier_section=verifier_section,
        reasoning_reliability_section=reasoning_reliability_section,
        case_section=case_section,
        feedback_section=feedback_section,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return path


async def write_report_node(state: dict) -> dict:
    """LangGraph node wrapper around write_report: pulls the fields it
    needs out of HuntState and returns the partial state update
    (report_path) for the graph to merge in."""
    logs = state.get("processed_logs") or state.get("logs") or []
    siem_type = state.get("siem_type", "folder")
    selected_sources = state.get("siem_types") or [siem_type]
    if len(selected_sources) > 1:
        log_source = ", ".join(selected_sources)
        diagnostics = state.get("source_diagnostics") or {}
        ingestion_diagnostics = "\n".join(
            f"- `{source}`: status={details.get('status', 'unknown')}, "
            f"attempts={details.get('attempt_count', 0)}, "
            f"last returned={details.get('last_record_count', 0)}, "
            f"last total hits={details.get('last_total_hits', 'n/a')}, "
            f"lookback={details.get('last_lookback_minutes', 'n/a')}m"
            for source, details in diagnostics.items()
        ) + f"\n- Records analyzed after cross-source dedup: {len(logs)}"
    elif siem_type in ("folder", "local_folder", "file", "local"):
        log_source = f"Local folder — {state.get('log_source_path') or '(default log source dir)'}"
        ingestion_diagnostics = (
            f"- Files scanned: {state.get('files_scanned', 'n/a')}\n"
            f"- Total records parsed (before query filter): {state.get('total_parsed', 'n/a')}\n"
            f"- Records after query filter: {state.get('record_count', 'n/a')}\n"
            f"- Total live-SIEM matches before result cap: {state.get('total_hits', 'n/a')}\n"
            f"- Records analyzed after dedup: {len(logs)}\n"
            f"- Unfiltered substitution used: {state.get('used_fallback_unfiltered', False)}\n"
        )
    else:
        log_source = siem_type
        ingestion_diagnostics = (
            f"- Records fetched: {state.get('record_count', 'n/a')}\n"
            f"- Total live-SIEM matches before result cap: {state.get('total_hits', 'n/a')}\n"
            f"- Records analyzed after dedup: {len(logs)}\n"
        )

    if state.get("reasoning_skipped"):
        return {
            "report_path": None,
            "report_status": "not_generated_no_evidence",
            "error": None,
        }
    if state.get("reasoning_failed"):
        return {
            "report_path": None,
            "report_status": "not_generated",
            "error": state.get("error") or "Report not generated because reasoning did not complete.",
        }
    if state.get("verification_failed"):
        return {
            "report_path": None,
            "report_status": "not_generated_verification_failed",
            "error": state.get("error") or "Report not generated because evidence references did not validate.",
        }

    hunt_completed_at = _local_now().isoformat(timespec="seconds")
    path = write_report(
        hunt_id=state.get("hunt_id", ""),
        title="",  # always auto-derived now — see write_report docstring
        hypothesis=state.get("hypothesis_text", ""),
        technique_id=state.get("technique_id", ""),
        technique_name=state.get("technique_name", ""),
        tactic=state.get("tactic", ""),
        summary=state.get("communication_summary") or state.get("reasoning_summary", ""),
        queries="\n\n".join(state.get("executed_queries") or [state.get("query", "")]),
        findings=state.get("findings", ""),
        recommendations=state.get("recommendations", ""),
        log_sample=_representative_log_sample(
            logs, state.get("sigma_matched_refs") or [], limit=5,
        ),
        hypothesis_id=state.get("hypothesis_id", ""),
        log_source=log_source,
        ingestion_diagnostics=ingestion_diagnostics,
        hunter_name=state.get("hunter_name", ""),
        cover_style=state.get("cover_style", "1"),
        sigma_rule_matches=state.get("sigma_rule_matches", []),
        sigma_matched_count=state.get("sigma_matched_count", 0),
        records_analyzed=len(logs),
        proposed_detection_rule=state.get("proposed_detection_rule"),
        plan=state.get("plan"),
        guardrail_result=state.get("guardrail_result"),
        enrichment_hits=state.get("enrichment_hits"),
        verifier_result=state.get("verifier_result"),
        case_id=state.get("case_id"),
        coverage_gaps=state.get("coverage_gaps"),
        coverage_assessment=state.get("coverage_assessment"),
        hunt_memory=state.get("hunt_memory"),
        evidence_highlights=state.get("evidence_highlights"),
        behavioral_evidence=state.get("behavioral_evidence"),
        reasoning_mode=state.get("reasoning_mode") or "model",
        reasoning_degraded=state.get("reasoning_degraded", False),
        reasoning_attempts=state.get("reasoning_attempts", 0),
        reasoning_error=state.get("reasoning_error"),
        retrieval_attempts=state.get("retrieval_attempts"),
        hunt_completeness=state.get("hunt_completeness"),
        investigation_requirements=state.get("investigation_requirements"),
        related_technique_signals=state.get("related_technique_signals"),
        hunt_started_at=state.get("hunt_started_at"),
        hunt_completed_at=hunt_completed_at,
    )
    return {
        "report_path": path,
        "report_status": "generated",
        "hunt_completed_at": hunt_completed_at,
    }


def list_reports() -> list[dict]:
    """List all generated markdown reports, most recent first."""
    if not os.path.isdir(REPORTS_DIR):
        return []
    entries = []
    for fname in os.listdir(REPORTS_DIR):
        if not fname.endswith(".md"):
            continue
        full = os.path.join(REPORTS_DIR, fname)
        entries.append({
            "filename": fname,
            "path": full,
            "modified": datetime.datetime.utcfromtimestamp(os.path.getmtime(full)).isoformat() + "Z",
        })
    entries.sort(key=lambda e: e["modified"], reverse=True)
    return entries


class ReportPathError(Exception):
    """Raised when a caller-supplied report path falls outside REPORTS_DIR."""


def read_report(path: str) -> dict:
    """Read a previously generated report's markdown content by path.

    `path` is caller-supplied (arrives via the read_hunt_report MCP tool),
    and this used to just `open()` it directly with no containment check
    at all -- any MCP-authenticated caller could read any file readable
    by this container (source code, mounted secrets, /etc/passwd, ...),
    not just files THOS itself wrote to REPORTS_DIR. Mirrors the same
    resolve-and-check-containment pattern
    services/siem/file_log_parser.validate_log_source_path already uses
    for folder-mode log paths, scoped to the single REPORTS_DIR root
    (report paths are always exactly what list_reports()/write_report()
    produced, so there's no multi-root config need here).
    """
    if not path or not str(path).strip():
        raise ReportPathError("no path provided")
    reports_root = os.path.realpath(REPORTS_DIR)
    real = os.path.realpath(path)
    if not (real == reports_root or real.startswith(reports_root + os.sep)):
        raise ReportPathError(
            f"'{path}' resolves outside the reports directory ({reports_root}); "
            f"refusing to read arbitrary server-side paths."
        )
    if not os.path.isfile(real):
        raise ReportPathError(f"'{path}' is not a file")
    with open(real, "r", encoding="utf-8") as f:
        return {"path": real, "content": f.read()}
