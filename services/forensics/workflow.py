"""Resource-bounded autonomous forensic specialist workflow."""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from services.forensics.analysis import (
    analyze_artifacts,
    apply_followup_tool_plan,
    build_timeline,
    correlate_evidence,
    verify_evidence,
)
from services.forensics.interpretation import interpret_forensic_evidence
from services.forensics.planner import plan_forensic_tools
from services.forensics.report import write_forensic_report
from services.reasoning.model_router import target_for

Progress = Callable[[dict], Awaitable[None]]


async def _emit(
    progress: Progress | None,
    *,
    event: str,
    stage: str,
    agent_name: str,
    activity: str,
    duration_ms: int | None = None,
    model_agent: str | None = None,
    output: dict | None = None,
) -> None:
    if not progress:
        return
    target = target_for(model_agent) if model_agent else None
    payload = {
        "event": event,
        "stage": stage,
        "agent_name": agent_name,
        "activity": activity,
        "model_tier": target.tier if target else None,
        "model_name": target.model if target else None,
    }
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms
    if output is not None:
        payload["output"] = output
    await progress(payload)


async def _run_stage(
    progress: Progress | None,
    *,
    stage: str,
    agent_name: str,
    activity: str,
    function,
    args: tuple = (),
    model_agent: str | None = None,
    threaded: bool = False,
) -> object:
    await _emit(
        progress,
        event="agent_started",
        stage=stage,
        agent_name=agent_name,
        activity=activity,
        model_agent=model_agent,
    )
    started = time.perf_counter()
    if threaded:
        output = await asyncio.to_thread(function, *args)
    else:
        output = await function(*args)
    duration_ms = int((time.perf_counter() - started) * 1000)
    summary = {}
    if isinstance(output, dict):
        summary = {
            key: output[key]
            for key in (
                "interpretation_status",
                "overall_disposition",
                "records_analyzed",
            )
            if key in output
        }
    await _emit(
        progress,
        event="agent_complete",
        stage=stage,
        agent_name=agent_name,
        activity=activity,
        duration_ms=duration_ms,
        model_agent=model_agent,
        output=summary,
    )
    return output


async def run_forensic_case(
    case_dir: str,
    progress: Progress | None = None,
) -> dict:
    verified = await _run_stage(
        progress,
        stage="forensic_intake",
        agent_name="Forensic Intake & Integrity Agent",
        activity=(
            "Verifies evidence containment, custody metadata, byte size, and SHA-256."
        ),
        function=verify_evidence,
        args=(case_dir,),
        threaded=True,
    )
    initial_plan = await _run_stage(
        progress,
        stage="forensic_planning",
        agent_name="Forensic Planning Agent",
        activity=(
            "Selects evidentiary tools from the live capability catalog for every artifact."
        ),
        function=plan_forensic_tools,
        args=(verified,),
        model_agent="forensic_planner",
    )
    triage = await _run_stage(
        progress,
        stage="forensic_artifact",
        agent_name="Forensic Artifact Execution Agent",
        activity=(
            "Executes only the validated model-selected tools within governed limits."
        ),
        function=analyze_artifacts,
        args=(verified, initial_plan),
        threaded=True,
    )
    followup_plan = await _run_stage(
        progress,
        stage="forensic_followup_planning",
        agent_name="Forensic Follow-up Planning Agent",
        activity=(
            "Reviews first-pass results and selects deeper installed memory, disk, document, or executable analysis when needed."
        ),
        function=plan_forensic_tools,
        args=(verified, triage),
        model_agent="forensic_followup",
    )
    followup_tools = sum(
        len(item.get("tools") or [])
        for item in followup_plan.get("artifacts") or []
        if isinstance(item, dict)
    )
    if followup_tools:
        triage = await _run_stage(
            progress,
            stage="forensic_followup_execution",
            agent_name="Forensic Deep Analysis Agent",
            activity=(
                "Executes the validated follow-up plan using installed forensic tools."
            ),
            function=apply_followup_tool_plan,
            args=(triage, verified, followup_plan),
            threaded=True,
        )
    correlation = await _run_stage(
        progress,
        stage="forensic_correlation",
        agent_name="Forensic Evidence Correlation Agent",
        activity=(
            "Builds literal rule, signature, IOC, anomaly, record, and tool facts without assigning a verdict."
        ),
        function=correlate_evidence,
        args=(triage,),
        threaded=True,
    )
    interpretation = await _run_stage(
        progress,
        stage="forensic_interpretation",
        agent_name="Forensic Interpretation Agent",
        activity=(
            "Correlates cited facts, evaluates alternatives, assigns evidence-supported dispositions, and records unresolved anomalies."
        ),
        function=interpret_forensic_evidence,
        args=(triage, correlation),
        model_agent="forensic_analysis",
    )
    timeline = await _run_stage(
        progress,
        stage="forensic_timeline",
        agent_name="Forensic Timeline Agent",
        activity=(
            "Builds a timestamp-ordered reconstruction with evidence references and supported ATT&CK mappings."
        ),
        function=build_timeline,
        args=(triage, interpretation),
        threaded=True,
    )
    report = await _run_stage(
        progress,
        stage="forensic_report",
        agent_name="Forensic Reporting Agent",
        activity=(
            "Writes the technical report with provenance, proven facts, unresolved anomalies, methodology, and limitations."
        ),
        function=write_forensic_report,
        args=(verified, triage, interpretation, timeline),
        threaded=True,
    )
    return {
        **report,
        "case": verified,
        "tool_plan": initial_plan,
        "followup_tool_plan": followup_plan,
        "interpretation": {
            key: interpretation.get(key)
            for key in (
                "summary",
                "overall_disposition",
                "interpretation_status",
            )
        },
    }
