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
  - NEW: a "Sigma Detections" section listing which real Sigma rules
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
> ## 📋 Executive Summary Cover
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
> ## 🛡️ SOC Analyst Cover Panel
>
> | Field | Value |
> |---|---|
> | Hunt ID | `{hunt_id}` |
> | Hypothesis ID | {hypothesis_id_or_na} |
> | MITRE ATT&CK | {technique_id_or_na} — {technique_name_or_na} ({tactic_or_na}) |
> | Log source | {log_source} |
> | Records analyzed | {records_analyzed} |
> | Sigma rules matched | {sigma_rules_matched} |
> | Sigma-flagged records | {sigma_matched_records} |
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
    provenance_note = {
        "curated": "",
        "base-technique-table+hearth-grounded": (
            "\n\n_Note: this technique's canonical MITRE name/tactic come from THOS's "
            "base-technique reference table; the description is grounded in this "
            "platform's own hunting-hypothesis data, not invented._"
        ),
        "hearth-grounded-only": (
            "\n\n_Note: no curated canonical name is available yet for this exact "
            "technique ID — tactic and description are grounded in this platform's own "
            "hunting-hypothesis data._"
        ),
    }.get(tech.get("source", ""), "")
    return (
        f"- **Technique:** {tech['name']} (`{tech['id']}`)\n"
        f"- **Tactic:** {tech['tactic']}\n"
        f"- **Description:** {tech['description']}\n"
        f"- **Typical data sources:** {data_sources}"
        f"{provenance_note}"
    )


def _render_sigma_section(sigma_rule_matches, sigma_matched_count: int, records_analyzed: int) -> str:
    if not sigma_rule_matches:
        return (
            f"No static Sigma rule matched any of the {records_analyzed} analyzed record(s) "
            f"for this hunt. (See Queries Executed / Sample Log Evidence below for what was "
            f"actually searched.)"
        )
    lines = [
        f"**{sigma_matched_count} of {records_analyzed} analyzed record(s) matched at least one "
        f"Sigma rule:**",
        "",
        "| Source | Rule ID | Title | Level | Records matched |",
        "|---|---|---|---|---|",
    ]
    source_label = {"sigmahq": "SigmaHQ", "thos": "THOS"}
    for rm in sigma_rule_matches:
        label = source_label.get(rm.get("source", ""), "—")
        lines.append(
            f"| {label} | `{rm['rule_id']}` | {rm['title']} | {rm['level']} | {rm['matched_count']} |"
        )
    return "\n".join(lines)


REPORT_TEMPLATE = """\
{cover}# Threat Hunt Report: {title}

## Hunt Timing & Audit Trail

| Event | Local timestamp |
|---|---|
| Hunt started | {hunt_started_at} |
| Hunt completed | {hunt_completed_at} |
| Report generated | {report_generated_at} |

_Timestamps include the local UTC offset and timezone. Hunt completion marks the end of the investigative agent stages immediately before report rendering._

---

## 🧭 Phase 1: Planning & Hypothesis Formulation
This phase establishes the hunt's objective, intelligence grounding, and execution path.

- **Hypothesis ID:** {hypothesis_id}
- **MITRE ATT&CK Tactic:** {tactic}
- **MITRE ATT&CK Technique:** {technique_name} ({technique_id})
- **Hunt Scope & Details:** {hypothesis}

### 🧠 MITRE ATT&CK Coverage
{mitre_section}

### 🧬 Prior Hunt Memory
{hunt_memory_section}

### 📋 Hunt Execution Plan
{hunt_plan_section}

---

## 📥 Phase 2: Ingestion & Normalization
This phase validates the collection, parsing, and filtering of telemetry data.

- **Telemetry Source:** {log_source}
- **Ingestion Status & Diagnostics:**
{ingestion_diagnostics}

### 🔍 SIEM Queries Executed
```
{queries}
```

### 🛡️ Guardrail Sentinel Scan
{guardrail_section}

---

## 🔌 Phase 3: Automated Detection & Enrichment
This phase applies deterministic detection rules and correlates threat intelligence.

### 🎯 Sigma Detections
{sigma_section}

### 📡 Threat Intelligence Enrichment
{threat_intel_section}

### ⚠️ Telemetry Coverage Gaps
{coverage_gaps_section}

---

## 🔎 Phase 4: Investigation & Deep Reasoning
This phase represents the core analytical assessment and evidence verification.

### ⚙️ Analysis Reliability
{reasoning_reliability_section}

### 📝 Security Findings
{findings}

### 🧐 Verifier / Critic Validation
{verifier_section}

### 📊 Representative Evidence Sample (bounded)
The sample prioritizes matcher hits and event diversity, and truncates raw detail fields to keep review practical.
```json
{log_sample}
```

---

## 🚀 Phase 5: Mitigation & Actionable Recommendations
This phase outlines response briefs, remediation steps, and proactive defense rules.

### 📢 Audience-Tailored Brief
> {summary}

### 🛠️ Actionable Recommendations
{recommendations}

### 📐 Proposed Detection Rule
{proposed_detection_rule}

---

## 🔄 Phase 6: Lifecycle Case Management & Feedback
This phase tracks the operational lifecycle of the hunt and feeds findings back into the platform.

### 🎟️ Case & Investigation Tracking
{case_section}

### ⚖️ Verification & Escalation Approvals
{approval_section}

### 📈 Continuous Learning & Feedback
{feedback_section}

---
*Generated by THOS (On-Prem AI Threat Hunting Operating System) — Ollama + LangGraph + FastMCP + RAG.*
*This report was produced by an AI reasoning pipeline built by Prasannakumar B Mundas. A human analyst should validate findings before action.*
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
                  hunt_memory: list[dict] | None = None,
                  approval_id: str | None = None,
                  human_approval_required: bool = False,
                  reasoning_mode: str = "model",
                  reasoning_degraded: bool = False,
                  reasoning_attempts: int = 0,
                  reasoning_error: str | None = None,
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
    normalized_hunt_started_at = _as_local_datetime(hunt_started_at, timestamp)
    normalized_hunt_completed_at = _as_local_datetime(hunt_completed_at, timestamp)
    resolved_title = title.strip() if title and title.strip() and title != hypothesis else ""
    if not resolved_title:
        resolved_title = _short_title(hypothesis_id, technique_id, technique_name, tactic, hypothesis)

    # Include a short hunt_id suffix so two reports generated in the same
    # second (same slug) never silently overwrite each other on disk.
    hunt_suffix = f"_{hunt_id[:8]}" if hunt_id else ""
    utc_timestamp = timestamp.astimezone(datetime.timezone.utc)
    filename = f"{utc_timestamp.strftime('%Y%m%dT%H%M%SZ')}_{_slugify(resolved_title)}{hunt_suffix}.md"
    path = os.path.join(REPORTS_DIR, filename)

    cover = _render_cover(
        cover_style=cover_style, hunt_id=hunt_id, hypothesis_id=hypothesis_id,
        technique_id=technique_id, technique_name=technique_name, tactic=tactic,
        log_source=log_source, hunter_name=hunter_name, records_analyzed=records_analyzed,
        sigma_rules_matched=len(sigma_rule_matches or []), sigma_matched_records=sigma_matched_count,
        findings=findings, timestamp=timestamp,
        verification_passed=(verifier_result or {}).get("status", "passed") == "passed",
        hunt_started_at=normalized_hunt_started_at,
        hunt_completed_at=normalized_hunt_completed_at,
    )
    mitre_section = _render_mitre_section(technique_id)
    sigma_section = _render_sigma_section(sigma_rule_matches or [], sigma_matched_count, records_analyzed)
    if reasoning_degraded:
        reasoning_reliability_section = (
            "⚠️ **Deterministic evidence fallback used.** The reasoning model did not produce a "
            f"valid response after {reasoning_attempts or 3} attempts. THOS still generated this "
            "report from Sigma matches, normalized telemetry, coverage analysis, and verified "
            "record citations. Human approval is required.\n\n"
            f"- **Recorded strike reasons:** `{reasoning_error or 'No valid model response'}`"
        )
    else:
        reasoning_reliability_section = (
            f"✅ **Model reasoning completed and validated.** Mode: `{reasoning_mode or 'model'}`; "
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
            hunt_memory_section += f"| `{h.get('hunt_id')}` | {date_str} | `{h.get('status')}` | {summary_str} |\n"

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
            "soc_tools": "Run Sigma and Indicator Matchers",
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
        guardrail_section = f"✅ **Clean:** No prompt injection markers or malicious instructions detected in untrusted log telemetry. (Scanned {gr_scanned} records)"
    else:
        guardrail_section = f"⚠️ **Flagged:** Detected {len(gr_hits)} record(s) containing instruction-like signatures in untrusted telemetry:\n\n"
        guardrail_section += "| Record Index | Log Field | Reason |\n|---|---|---|\n"
        for hit in gr_hits:
            guardrail_section += f"| {hit.get('record_index')} | `{hit.get('field')}` | {hit.get('reason')} |\n"

    # Format Threat Intel section
    if not enrichment_hits:
        threat_intel_section = "✅ No observable IOCs (IPs, domains, file hashes) matched the local threat intelligence blocklist."
    else:
        threat_intel_section = f"Correlated {len(enrichment_hits)} observable indicator(s) against the local blocklist:\n\n"
        threat_intel_section += "| Indicator / IOC | Log Record Index | Source | Threat Metadata |\n|---|---|---|---|\n"
        for hit in enrichment_hits:
            threat_intel_section += f"| `{hit.get('indicator')}` | {hit.get('record_index')} | `{hit.get('source')}` | {hit.get('metadata')} |\n"

    # Format Coverage Gaps section
    if not coverage_gaps:
        coverage_gaps_section = "✅ **Telemetry Health Passed:** No critical coverage gaps or ingestion errors detected during execution."
    else:
        coverage_gaps_section = "⚠️ **Telemetry Coverage Gaps & Health Alerts Identified:**\n\n"
        for gap in coverage_gaps:
            coverage_gaps_section += f"- {gap}\n"

    # Format Verifier result
    vr = verifier_result or {}
    vr_status = vr.get("status", "passed")
    vr_checked = vr.get("checked_citations", 0)
    vr_invalid = vr.get("invalid_references") or []
    vr_reason = vr.get("reason", "")
    if vr_status == "passed":
        verifier_section = f"✅ **Passed:** All cited references validated successfully. The verifier confirmed that all `{vr_checked}` evidence citations (`ref: N`) point to valid records in the processed logs."
    else:
        verifier_section = f"❌ **Failed:** Evidence verification failed due to: *{vr_reason}*.\n\n"
        if vr_invalid:
            verifier_section += f"- **Invalid References:** {', '.join(str(r) for r in vr_invalid)}\n"
        if human_approval_required:
            verifier_section += "- ⚠️ **Escalation Triggered:** Analyst review and human approval are required to resolve citation discrepancies."

    # Format Case section
    if case_id:
        prio = "High 🚨" if vr_status != "passed" else "Medium ⚠️"
        case_section = (
            f"📂 **Active Case Created:**\n"
            f"- **Case ID:** `{case_id}`\n"
            f"- **Status:** `Open` / `Pending Analyst Review`\n"
            f"- **Priority:** {prio}\n\n"
            f"_An investigation has been automatically created in the auditing database to track findings triage and resolution._"
        )
    else:
        case_section = "No case was generated for this hunt. (Telemetry and findings were clean, or audit write failed)"

    # Format Approval section
    if human_approval_required or approval_id:
        approval_section = (
            f"⚖️ **Pending Approval Action:**\n"
            f"- **Approval ID:** `{approval_id or 'n/a'}`\n"
            f"- **Status:** `Pending` / `Requires Analyst Sign-off`\n\n"
            f"_Analyst approval is required before promotion of detection rules or case closure. Actions can be decided using the `/approvals` API endpoint._"
        )
    else:
        approval_section = "✅ No escalations or pending approvals required."

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
        cover=cover,
        title=resolved_title,
        hunt_id=hunt_id,
        timestamp=timestamp.isoformat(),
        hunt_started_at=_format_local_timestamp(normalized_hunt_started_at),
        hunt_completed_at=_format_local_timestamp(normalized_hunt_completed_at),
        report_generated_at=_format_local_timestamp(timestamp),
        hypothesis_id=hypothesis_id or "n/a",
        log_source=log_source or "mock (synthetic logs)",
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
        sigma_section=sigma_section,
        proposed_detection_rule=(f"```yaml\n{proposed_detection_rule}```\n\n_Proposal only; human approval is required before promotion._" if proposed_detection_rule else "_No rule proposal generated for this hunt._"),
        hunt_memory_section=hunt_memory_section,
        hunt_plan_section=hunt_plan_section,
        guardrail_section=guardrail_section,
        threat_intel_section=threat_intel_section,
        coverage_gaps_section=coverage_gaps_section,
        verifier_section=verifier_section,
        reasoning_reliability_section=reasoning_reliability_section,
        case_section=case_section,
        approval_section=approval_section,
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
    siem_type = state.get("siem_type", "mock")
    if siem_type in ("folder", "local_folder", "file", "local"):
        log_source = f"Local folder — {state.get('log_source_path') or '(default log source dir)'}"
        ingestion_diagnostics = (
            f"- Files scanned: {state.get('files_scanned', 'n/a')}\n"
            f"- Total records parsed (before query filter): {state.get('total_parsed', 'n/a')}\n"
            f"- Records after query filter: {state.get('record_count', 'n/a')}\n"
            f"- Total live-SIEM matches before result cap: {state.get('total_hits', 'n/a')}\n"
            f"- Records analyzed after dedup: {len(logs)}\n"
            f"- Query filter fell back to unfiltered (matched nothing): {state.get('used_fallback_unfiltered', 'n/a')}\n"
        )
    else:
        log_source = siem_type
        ingestion_diagnostics = (
            f"- Records fetched: {state.get('record_count', 'n/a')}\n"
            f"- Total live-SIEM matches before result cap: {state.get('total_hits', 'n/a')}\n"
            f"- Records analyzed after dedup: {len(logs)}\n"
        )

    if state.get("reasoning_failed"):
        return {
            "report_path": None,
            "report_status": "not_generated",
            "error": state.get("error") or "Report not generated because reasoning did not complete.",
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
        queries=state.get("query", ""),
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
        hunt_memory=state.get("hunt_memory"),
        approval_id=state.get("approval_id"),
        human_approval_required=state.get("human_approval_required", False),
        reasoning_mode=state.get("reasoning_mode") or "model",
        reasoning_degraded=state.get("reasoning_degraded", False),
        reasoning_attempts=state.get("reasoning_attempts", 0),
        reasoning_error=state.get("reasoning_error"),
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
