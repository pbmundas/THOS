#!/usr/bin/env python3
"""Measure historical THOS hunt, agent, and file-scan capacity.

Run inside the Orchestrator image so the benchmark uses the deployed
dependencies, rule volumes, runtime configuration, and audit database:

  python scripts/benchmark-thos.py --output-dir /repo/work/benchmarks \
      --yara-sample /data/log_sources/forensic/<case>/<sample>

The legacy synthetic rule microbenchmark is disabled by default. Use
scripts/enterprise-regression.py for operational capacity measurements
against live telemetry.
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import time
from typing import Any

import psycopg


REPO_ROOT = Path(__file__).resolve().parents[1]

TACTIC_SEVERITY = {
    "Credential Access": "critical",
    "Defense Impairment": "critical",
    "Exfiltration": "critical",
    "Impact": "critical",
    "Initial Access": "high",
    "Lateral Movement": "high",
    "Persistence": "high",
    "Privilege Escalation": "high",
    "Stealth": "high",
    "Collection": "medium",
    "Command and Control": "medium",
    "Defense Evasion": "medium",
    "Discovery": "medium",
    "Execution": "medium",
    "Reconnaissance": "low",
    "Resource Development": "low",
}


def _severity(item: dict[str, Any]) -> str:
    explicit = str(item.get("severity") or "").strip().lower()
    if explicit:
        return explicit
    return TACTIC_SEVERITY.get(str(item.get("tactic") or "").strip(), "medium")


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return float(ordered[index])


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _fetch_rows(query: str) -> list[dict[str, Any]]:
    dsn = os.environ.get("POSTGRES_DSN", "")
    if not dsn:
        return []
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [column.name for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _historical_timings() -> tuple[list[dict], list[dict], dict]:
    hunts = _fetch_rows("""
        SELECT h.hunt_id::text, h.hypothesis_id, h.status,
               EXTRACT(EPOCH FROM (h.updated_at - h.created_at)) * 1000 AS duration_ms,
               h.created_at, h.updated_at, h.outcome
        FROM hunts h
        ORDER BY h.created_at
    """)
    steps = _fetch_rows("""
        SELECT hs.node_name, hs.agent_name, hs.model_tier, hs.model_name,
               hs.duration_ms, h.hypothesis_id, h.status
        FROM hunt_steps hs
        JOIN hunts h ON h.hunt_id = hs.hunt_id
        WHERE hs.duration_ms IS NOT NULL
        ORDER BY hs.created_at
    """)
    normalized_hunts = [{
        **row,
        "duration_ms": round(float(row.get("duration_ms") or 0), 3),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else "",
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else "",
        "outcome": json.dumps(row.get("outcome") or {}, default=str, separators=(",", ":")),
    } for row in hunts]
    grouped: dict[tuple, list[float]] = defaultdict(list)
    for row in steps:
        grouped[(
            row.get("node_name"), row.get("agent_name"),
            row.get("model_tier"), row.get("model_name"),
        )].append(float(row.get("duration_ms") or 0))
    agents = []
    for key, values in grouped.items():
        node, agent, tier, model = key
        agents.append({
            "node_name": node or "",
            "agent_name": agent or "",
            "model_tier": tier or "",
            "model_name": model or "",
            "executions": len(values),
            "avg_duration_ms": round(statistics.mean(values), 3),
            "median_duration_ms": round(statistics.median(values), 3),
            "p95_duration_ms": round(_percentile(values, 0.95), 3),
            "max_duration_ms": round(max(values), 3),
        })
    agents.sort(key=lambda row: row["p95_duration_ms"], reverse=True)
    completed = [
        float(row["duration_ms"]) for row in normalized_hunts
        if row["status"] == "completed" and float(row["duration_ms"]) > 0
    ]
    summary = {
        "historical_hunts": len(normalized_hunts),
        "completed_hunts": len(completed),
        "completed_avg_ms": round(statistics.mean(completed), 3) if completed else 0,
        "completed_median_ms": round(statistics.median(completed), 3) if completed else 0,
        "completed_p95_ms": round(_percentile(completed, 0.95), 3),
    }
    return normalized_hunts, agents, summary


def _hypothesis_estimates(
    historical: list[dict],
    baseline_ms: int,
) -> tuple[list[dict], dict]:
    upstream = json.loads(
        (REPO_ROOT / "data/knowledge_base/hearth/hearth_full.json").read_text(
            encoding="utf-8"
        )
    )
    required = json.loads(
        (REPO_ROOT / "services/hunting/data/required_gap_hypotheses.json").read_text(
            encoding="utf-8"
        )
    )
    catalog = [*upstream, *required]
    by_hypothesis: dict[str, list[float]] = defaultdict(list)
    for row in historical:
        if row["status"] == "completed" and row.get("hypothesis_id"):
            by_hypothesis[str(row["hypothesis_id"])].append(float(row["duration_ms"]))

    rows = []
    for item in catalog:
        measured = by_hypothesis.get(str(item["id"]), [])
        estimate = statistics.median(measured) if measured else baseline_ms
        rows.append({
            "hypothesis_id": item["id"],
            "title": item.get("title", ""),
            "technique": item.get("technique", ""),
            "tactic": item.get("tactic", ""),
            "severity": _severity(item),
            "historical_runs": len(measured),
            "historical_median_ms": round(statistics.median(measured), 3) if measured else "",
            "estimated_duration_ms": round(estimate, 3),
            "estimated_duration_minutes": round(estimate / 60_000, 3),
            "estimate_basis": "exact historical median" if measured else "20-minute true-positive planning baseline",
            "runnable_sigma_rules": item.get("runnable_sigma_rules", ""),
        })
    total_ms = sum(float(row["estimated_duration_ms"]) for row in rows)
    return rows, {
        "hypothesis_count": len(rows),
        "sequential_total_ms": round(total_ms, 3),
        "sequential_total_hours": round(total_ms / 3_600_000, 3),
    }


def _representative_records() -> list[dict]:
    return [
        {
            "timestamp": "2026-07-27T10:00:00Z",
            "host": "benchmark-win",
            "user": "analyst",
            "event": event,
            "src_ip": "10.0.0.10",
            "dst_ip": "198.51.100.20",
            "detail": detail,
        }
        for event, detail in [
            ("1", "Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -EncodedCommand AAA ParentImage=cmd.exe"),
            ("3", "Image=powershell.exe DestinationIp=198.51.100.20 DestinationPort=443"),
            ("7", "ImageLoaded=C:\\Temp\\unsigned.dll Image=svchost.exe"),
            ("10", "SourceImage=procdump.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010"),
            ("11", "TargetFilename=C:\\Users\\Public\\payload.exe Image=certutil.exe"),
            ("13", "TargetObject=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Details=payload.exe"),
            ("22", "QueryName=rare-example.invalid Image=powershell.exe"),
            ("4104", "ScriptBlockText=Invoke-WebRequest http://example.invalid/payload"),
            ("4624", "TargetUserName=administrator LogonType=3 IpAddress=10.0.0.20"),
            ("4688", "NewProcessName=C:\\Windows\\System32\\rundll32.exe CommandLine=rundll32.exe javascript:"),
            ("4698", "TaskName=Updater TaskContent=powershell.exe -enc AAA"),
            ("4720", "TargetUserName=backup_admin SubjectUserName=administrator"),
            ("7045", "ServiceName=Updater ImagePath=C:\\Users\\Public\\payload.exe"),
            ("alert", "Suricata alert suspicious outbound TLS connection"),
        ]
    ]


def _sigma_timings() -> tuple[list[dict], dict]:
    from services.detection import sigma_engine, sigmahq_engine

    records = _representative_records()
    record_tokens = [
        set(sigmahq_engine._TOKEN_RE.findall(
            " ".join(str(value) for value in record.values()).lower()
        ))
        for record in records
    ]
    cold_started = time.perf_counter()
    community = sigmahq_engine.load_rules()
    local = sigma_engine.load_rules()
    cold_load_ms = (time.perf_counter() - cold_started) * 1000

    rows: list[dict] = []
    total_started = time.perf_counter()
    for rule in community:
        started = time.perf_counter_ns()
        matches = 0
        for record, tokens in zip(records, record_tokens):
            if rule.gate_tokens is not None and rule.gate_tokens.isdisjoint(tokens):
                continue
            if any(predicate(record) for predicate in rule.predicates):
                matches += 1
        duration_ns = time.perf_counter_ns() - started
        rows.append({
            "source": "SigmaHQ",
            "rule_id": rule.rule_id,
            "title": rule.title,
            "level": rule.level,
            "techniques": ",".join(
                tag.removeprefix("attack.").upper()
                for tag in rule.tags if tag.lower().startswith("attack.t")
            ),
            "records_benchmarked": len(records),
            "matched_records": matches,
            "evaluation_ms": round(duration_ns / 1_000_000, 6),
        })
    for rule in local:
        started = time.perf_counter_ns()
        matches = sum(sigma_engine.evaluate_rule(rule, record) for record in records)
        duration_ns = time.perf_counter_ns() - started
        rows.append({
            "source": "THOS",
            "rule_id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "level": rule.get("level", "medium"),
            "techniques": ",".join(
                str(tag).removeprefix("attack.").upper()
                for tag in rule.get("tags", []) if str(tag).lower().startswith("attack.t")
            ),
            "records_benchmarked": len(records),
            "matched_records": matches,
            "evaluation_ms": round(duration_ns / 1_000_000, 6),
        })
    evaluation_ms = (time.perf_counter() - total_started) * 1000
    return rows, {
        "rules": len(rows),
        "records": len(records),
        "cold_rule_load_ms": round(cold_load_ms, 3),
        "full_corpus_evaluation_ms": round(evaluation_ms, 3),
        "avg_rule_evaluation_ms": round(
            statistics.mean(float(row["evaluation_ms"]) for row in rows), 6
        ),
        "p95_rule_evaluation_ms": round(_percentile(
            [float(row["evaluation_ms"]) for row in rows], 0.95
        ), 6),
    }


def _yara_timings(sample: Path | None) -> tuple[list[dict], dict]:
    from services.detection import yara_engine

    catalog = yara_engine.catalog()
    summary = yara_engine.catalog_summary()
    result: dict[str, Any] = {}
    duration_ms = 0.0
    if sample and sample.is_file():
        started = time.perf_counter()
        result = yara_engine.scan_paths([sample])
        duration_ms = (time.perf_counter() - started) * 1000
    rows = [{
        "rule_id": item.get("id", ""),
        "rule_name": item.get("rule_name", ""),
        "title": item.get("title", ""),
        "source": item.get("source", ""),
        "severity": item.get("severity", ""),
        "category": item.get("category", ""),
        "compilation_status": item.get("compilation_status", ""),
        "enabled": item.get("enabled", False),
        "shared_bundle_scan_ms": round(duration_ms, 3) if duration_ms else "",
        "marginal_per_rule_scan_ms": 0 if duration_ms else "",
    } for item in catalog]
    return rows, {
        **summary,
        "catalog_entries": len(catalog),
        "sample_path": str(sample or ""),
        "sample_bytes": sample.stat().st_size if sample and sample.is_file() else 0,
        "shared_bundle_scan_ms": round(duration_ms, 3),
        "match_count": result.get("match_count", 0),
        "note": (
            "YARA evaluates the enabled rules as one compiled bundle. Schedule one "
            "catalog scan per evidence root; per-rule schedules repeat the same bundle scan."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--baseline-minutes", type=float, default=20.0)
    parser.add_argument("--yara-sample", type=Path)
    parser.add_argument(
        "--include-synthetic-rule-microbenchmark",
        action="store_true",
        help="Run the isolated developer-only 14-record rule microbenchmark.",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    historical, agents, historical_summary = _historical_timings()
    hypotheses, hypothesis_summary = _hypothesis_estimates(
        historical, int(args.baseline_minutes * 60_000)
    )
    if args.include_synthetic_rule_microbenchmark:
        sigma_rows, sigma_summary = _sigma_timings()
        sigma_summary["synthetic_microbenchmark"] = True
        sigma_summary["operational_capacity_evidence"] = False
    else:
        sigma_rows = []
        sigma_summary = {
            "skipped": True,
            "synthetic_microbenchmark": False,
            "operational_capacity_evidence": False,
            "note": (
                "Synthetic microbenchmark disabled. Use enterprise-regression.py "
                "with live telemetry for operational measurements."
            ),
        }
    yara_rows, yara_summary = _yara_timings(args.yara_sample)

    _write_csv(args.output_dir / "historical_hunt_timings.csv", historical)
    _write_csv(args.output_dir / "agent_timings.csv", agents)
    _write_csv(args.output_dir / "hypothesis_duration_estimates.csv", hypotheses)
    _write_csv(args.output_dir / "sigma_rule_timings.csv", sigma_rows)
    _write_csv(args.output_dir / "yara_rule_timings.csv", yara_rows)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "historical": historical_summary,
        "hypotheses": hypothesis_summary,
        "sigma": sigma_summary,
        "yara": yara_summary,
        "resources": {
            "ollama_cpu_limit": os.environ.get("OLLAMA_CPU_LIMIT", "4 (compose default)"),
            "ollama_memory_limit": os.environ.get("OLLAMA_MEM_LIMIT", "8g (compose default)"),
            "orchestrator_cpu_limit": os.environ.get("ORCHESTRATOR_CPU_LIMIT", "2 (compose default)"),
            "orchestrator_memory_limit": os.environ.get("ORCHESTRATOR_MEM_LIMIT", "2g (compose default)"),
            "hunt_concurrency": 1,
            "sigma_query_concurrency": int(os.environ.get("SIGMA_QUERY_CONCURRENCY", "6")),
            "scheduled_sigma_concurrency": int(os.environ.get("THOS_SCHEDULED_SIGMA_CONCURRENCY", "2")),
            "scheduled_yara_concurrency": int(os.environ.get("THOS_SCHEDULED_YARA_CONCURRENCY", "1")),
        },
    }
    (args.output_dir / "benchmark_summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
