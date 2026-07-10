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

from services.knowledge import mitre

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/data/reports")

MAX_TITLE_LEN = 90


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
> initiated {generated_human}.
>
> **Bottom line:** {bottom_line}
>
> **Analyst / requested by:** {hunter_name}
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
> | Generated | {timestamp} UTC |

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
                   findings: str, timestamp: datetime.datetime) -> str:
    generated_human = timestamp.strftime("%Y-%m-%d %H:%M UTC")
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
            timestamp=timestamp.isoformat(),
        )
    return COVER_EXECUTIVE_TEMPLATE.format(
        technique_name_or_na=technique_name or "an unspecified technique",
        tactic_or_na=tactic or "unspecified tactic",
        generated_human=generated_human,
        bottom_line=_bottom_line(findings, sigma_matched_records),
        hunter_name=hunter_name or "anonymous",
    )


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

- **Hunt ID:** `{hunt_id}`
- **Generated:** {timestamp} UTC
- **Hypothesis ID:** {hypothesis_id}
- **MITRE ATT&CK:** {technique_id} — {technique_name} ({tactic})
- **Log Source:** {log_source}

## Hypothesis

{hypothesis}

## Log Ingestion Diagnostics

{ingestion_diagnostics}

## Executive Summary

{summary}

## MITRE ATT&CK Coverage

{mitre_section}

## Queries Executed

```
{queries}
```

## Sigma Detections

{sigma_section}

## Findings

{findings}

## Recommendations

{recommendations}

## Sample Log Evidence

```json
{log_sample}
```

---
*Generated by THOS (On-Prem AI Threat Hunting Platform) — Ollama + LangGraph + FastMCP + RAG.*
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
                  sigma_matched_count: int = 0, records_analyzed: int = 0) -> str:
    """Render the markdown report and write it to disk. Returns the file path.

    `title`, if not given (empty string), is now derived automatically
    from technique/tactic/hypothesis_id via `_short_title` — callers no
    longer need to (and should not) pass the full hypothesis text as the
    title.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = datetime.datetime.utcnow()
    resolved_title = title.strip() if title and title.strip() and title != hypothesis else ""
    if not resolved_title:
        resolved_title = _short_title(hypothesis_id, technique_id, technique_name, tactic, hypothesis)

    # Include a short hunt_id suffix so two reports generated in the same
    # second (same slug) never silently overwrite each other on disk.
    hunt_suffix = f"_{hunt_id[:8]}" if hunt_id else ""
    filename = f"{timestamp.strftime('%Y%m%dT%H%M%SZ')}_{_slugify(resolved_title)}{hunt_suffix}.md"
    path = os.path.join(REPORTS_DIR, filename)

    cover = _render_cover(
        cover_style=cover_style, hunt_id=hunt_id, hypothesis_id=hypothesis_id,
        technique_id=technique_id, technique_name=technique_name, tactic=tactic,
        log_source=log_source, hunter_name=hunter_name, records_analyzed=records_analyzed,
        sigma_rules_matched=len(sigma_rule_matches or []), sigma_matched_records=sigma_matched_count,
        findings=findings, timestamp=timestamp,
    )
    mitre_section = _render_mitre_section(technique_id)
    sigma_section = _render_sigma_section(sigma_rule_matches or [], sigma_matched_count, records_analyzed)

    content = REPORT_TEMPLATE.format(
        cover=cover,
        title=resolved_title,
        hunt_id=hunt_id,
        timestamp=timestamp.isoformat(),
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
            f"- Records analyzed after dedup: {len(logs)}\n"
            f"- Query filter fell back to unfiltered (matched nothing): {state.get('used_fallback_unfiltered', 'n/a')}\n"
        )
    else:
        log_source = siem_type
        ingestion_diagnostics = f"- Records fetched: {state.get('record_count', 'n/a')}\n- Records analyzed after dedup: {len(logs)}\n"

    path = write_report(
        hunt_id=state.get("hunt_id", ""),
        title="",  # always auto-derived now — see write_report docstring
        hypothesis=state.get("hypothesis_text", ""),
        technique_id=state.get("technique_id", ""),
        technique_name=state.get("technique_name", ""),
        tactic=state.get("tactic", ""),
        summary=state.get("reasoning_summary", ""),
        queries=state.get("query", ""),
        findings=state.get("findings", ""),
        recommendations=state.get("recommendations", ""),
        log_sample=str(logs[:5]),
        hypothesis_id=state.get("hypothesis_id", ""),
        log_source=log_source,
        ingestion_diagnostics=ingestion_diagnostics,
        hunter_name=state.get("hunter_name", ""),
        cover_style=state.get("cover_style", "1"),
        sigma_rule_matches=state.get("sigma_rule_matches", []),
        sigma_matched_count=state.get("sigma_matched_count", 0),
        records_analyzed=len(logs),
    )
    return {"report_path": path}


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
