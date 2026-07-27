"""Resource-bounded coordinator for the THOS forensic specialist agents."""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from services.forensics.analysis import (
    analyze_artifacts,
    build_timeline,
    correlate_evidence,
    verify_evidence,
)
from services.forensics.report import write_forensic_report

Progress = Callable[[dict], Awaitable[None]]

STAGES = (
    ("forensic_intake", "Forensic Intake & Integrity Agent", "Verifies case containment, custody metadata, file size, and full SHA-256.", verify_evidence),
    ("forensic_artifact", "Forensic Artifact Analysis Agent", "Identifies and parses artifacts, inventories archives, and checks disk-image tooling.", analyze_artifacts),
    ("forensic_correlation", "Forensic Detection Correlation Agent", "Runs detection-rule correlation, IOC extraction, anomaly scoring, and review-keyword triage.", correlate_evidence),
    ("forensic_timeline", "Forensic Timeline Agent", "Builds a timestamp-ordered event reconstruction with evidence references.", build_timeline),
)


async def run_forensic_case(case_dir: str, progress: Progress | None = None) -> dict:
    values: dict[str, object] = {}
    for stage_id, agent_name, activity, function in STAGES:
        if progress:
            await progress({
                "event": "agent_started", "stage": stage_id, "agent_name": agent_name,
                "activity": activity, "model_tier": None, "model_name": None,
            })
        started = time.perf_counter()
        if stage_id == "forensic_intake":
            output = await asyncio.to_thread(function, case_dir)
        elif stage_id == "forensic_artifact":
            output = await asyncio.to_thread(function, values["forensic_intake"])
        elif stage_id == "forensic_correlation":
            output = await asyncio.to_thread(function, values["forensic_artifact"])
        else:
            output = await asyncio.to_thread(
                function,
                values["forensic_artifact"],
                values["forensic_correlation"],
            )
        values[stage_id] = output
        duration_ms = int((time.perf_counter() - started) * 1000)
        if progress:
            await progress({
                "event": "agent_complete", "stage": stage_id, "agent_name": agent_name,
                "activity": activity, "duration_ms": duration_ms,
                "model_tier": None, "model_name": None,
            })

    stage_id = "forensic_report"
    agent_name = "Forensic Reporting Agent"
    activity = "Writes the technical report with integrity, methodology, limitations, and legal-review sections."
    if progress:
        await progress({
            "event": "agent_started", "stage": stage_id, "agent_name": agent_name,
            "activity": activity, "model_tier": None, "model_name": None,
        })
    started = time.perf_counter()
    result = await asyncio.to_thread(
        write_forensic_report,
        values["forensic_intake"],
        values["forensic_artifact"],
        values["forensic_correlation"],
        values["forensic_timeline"],
    )
    duration_ms = int((time.perf_counter() - started) * 1000)
    if progress:
        await progress({
            "event": "agent_complete", "stage": stage_id, "agent_name": agent_name,
            "activity": activity, "duration_ms": duration_ms,
            "model_tier": None, "model_name": None,
        })
    return {**result, "case": values["forensic_intake"]}
