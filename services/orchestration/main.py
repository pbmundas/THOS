"""
THOS Orchestrator API.

Thin FastAPI wrapper around the compiled LangGraph state machine
(app.graph.compiled_graph). This is the service the chat-ui (or any
other client — Slack bot, CLI, ticketing integration, etc.) talks to.

Endpoints:
  GET  /health           liveness check
  GET  /hypotheses       list HEARTH hypotheses (optionally filtered by tactic)
  POST /hunt             run one full hunt end-to-end, return the final state
  POST /hunt/stream      same, but streamed as newline-delimited JSON, one
                         line per LangGraph node completion (for UIs that
                         want to show live progress instead of a single
                         blocking wait)

Extension point (Phase 2+): add a `/hunt/{hunt_id}/continue` endpoint that
resumes a paused graph using LangGraph's checkpointing, instead of always
running start-to-finish.
"""
import base64
import json
import logging
import os
import re
import secrets
import uuid
import asyncio
import time
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from services.orchestration.graph import compiled_graph
from services.mcp import mcp_client
from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState
from services.observability import audit, cache
from services.observability.logging_config import (
    configure_logging,
    reset_hunt_context,
    set_hunt_context,
)
from services.runtime_config import get_value
from services.agents.registry import agent_by_graph_node
from services.reasoning.model_router import (
    reset_model_workload,
    set_model_workload,
    target_for,
)
from services.risk.risk_agent import (
    analyze_actionable_risks,
    apply_risk_resolutions,
    filter_risk_payload,
    risk_source_version,
)
from services.detection.detection_analysis_agent import analyze_detection
from services.security.configuration import required_secret

# As early as possible: attaches one stdout JSON handler to the root
# logger so every logger.*() call in this process (this module, graph
# nodes, mcp_client, audit, retry, ...) emits structured, aggregator-
# ready lines instead of relying on Python's unformatted default
# handler. See services/observability/logging_config.py.
configure_logging("thos-orchestrator")
logger = logging.getLogger(__name__)

app = FastAPI(title="THOS Orchestrator", version="1.0.0")
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/data/reports"))

# --- Auth ---------------------------------------------------------------
# This service can run hunts (which call every SOC tool via MCP) and read
# every generated report. It sits on the network right alongside the chat
# UI, so it needs its own credential check rather than trusting that only
# the chat UI can reach it. Callers must send
# `Authorization: Bearer <ORCHESTRATOR_API_KEY>`. Same weak-default /
# loud-warning pattern as MCP_AUTH_TOKEN below — works out of the box for
# local dev, must be overridden with a real secret before this is
# reachable by anyone else.
ORCHESTRATOR_API_KEY = required_secret("ORCHESTRATOR_API_KEY")


async def require_api_key(authorization: str = Header(default="")):
    """FastAPI dependency: every functional endpoint requires a bearer
    token matching ORCHESTRATOR_API_KEY. /health is deliberately exempt so
    container healthchecks/orchestration tooling can still probe liveness
    without a credential."""
    expected = f"Bearer {ORCHESTRATOR_API_KEY}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")


# The rate limiter (services/observability/cache.rate_limit_check) was fully
# implemented but never called anywhere — /hunt had zero protection against
# a burst of requests. Bucketed per hunter_name so one noisy caller can't
# starve everyone else's budget; both knobs are env-configurable per deploy.
HUNT_RATE_LIMIT = int(os.environ.get("HUNT_RATE_LIMIT_PER_WINDOW", "10"))
HUNT_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("HUNT_RATE_LIMIT_WINDOW_SECONDS", "60"))
MAX_REASONING_FOLLOWUPS = int(os.environ.get(
    "MAX_REASONING_FOLLOWUPS",
    str(get_value("autonomy", "max_reasoning_followups", default=2)),
))


async def _enforce_hunt_rate_limit(hunter_name: str):
    bucket = f"hunt:{hunter_name or 'anonymous'}"
    # cache.rate_limit_check uses a sync redis client — offload so it can't
    # block the event loop out from under concurrent hunts.
    allowed = await asyncio.to_thread(
        cache.rate_limit_check, bucket, HUNT_RATE_LIMIT, HUNT_RATE_LIMIT_WINDOW_SECONDS
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded for hunter '{hunter_name}': max "
                f"{HUNT_RATE_LIMIT} hunts per {HUNT_RATE_LIMIT_WINDOW_SECONDS}s. "
                f"Please retry shortly."
            ),
        )


# --- Platform-wide hunt gate ----------------------------------------------
# Hunts are intentionally serialized across every user of this Orchestrator.
# A second start is rejected immediately so the UI can explain the active lock
# instead of silently queueing another hypothesis behind it.
_active_hunt_count = 0
_active_hunt_lock = asyncio.Lock()
_background_hunts: set[asyncio.Task] = set()
_background_forensics: set[asyncio.Task] = set()
_background_risk_refreshes: set[asyncio.Task] = set()
_forensic_start_lock = asyncio.Lock()
_forensic_worker_slot = asyncio.Semaphore(1)
_risk_refresh_lock = asyncio.Lock()
_risk_refresh_reasons: set[str] = set()
_risk_refresh_force = False
_risk_refresh_task: asyncio.Task | None = None


def _background_hunt_done(task: asyncio.Task) -> None:
    _background_hunts.discard(task)
    if task.cancelled():
        return
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return
    if error is not None:
        logger.error("background hunt worker crashed: %s", error)


def _background_forensic_done(task: asyncio.Task) -> None:
    _background_forensics.discard(task)
    if task.cancelled():
        return
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return
    if error is not None:
        logger.error("background forensic worker crashed: %s", error)


def _background_risk_done(task: asyncio.Task) -> None:
    global _risk_refresh_task
    _background_risk_refreshes.discard(task)
    if _risk_refresh_task is task:
        _risk_refresh_task = None
    if task.cancelled():
        return
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return
    if error is not None:
        logger.error("background risk refresh crashed: %s", error)


async def _refresh_risk_snapshot(reason: str, force: bool = False) -> dict:
    """Materialize model-owned risks after persisted evidence changes."""
    async with _risk_refresh_lock:
        hunts, detections = await asyncio.gather(
            audit.risk_source_hunts(),
            audit.risk_source_detections(),
        )
        source_version = await asyncio.to_thread(
            risk_source_version, hunts, detections, REPORTS_DIR
        )
        existing = await audit.get_risk_snapshot()
        existing_payload = (
            existing.get("payload")
            if existing and isinstance(existing.get("payload"), dict)
            else {}
        )
        existing_agent = (
            existing_payload.get("agent")
            if isinstance(existing_payload.get("agent"), dict)
            else {}
        )
        if (
            not force
            and existing
            and existing.get("status") == "completed"
            and existing.get("source_version") == source_version
            and not bool(existing_agent.get("degraded"))
            and not bool(existing_agent.get("errors"))
        ):
            return existing_payload
        await audit.mark_risk_refresh_started(source_version, reason)
        try:
            result = await analyze_actionable_risks(
                hunts,
                detections,
                REPORTS_DIR,
                max(1, min(
                    int(get_value(
                        "autonomy", "risk_snapshot_limit", default=2000
                    )),
                    2000,
                )),
                previous_payload=(
                    existing_payload
                    if existing and not force
                    else None
                ),
            )
            await audit.save_risk_snapshot(source_version, result, reason)
            await audit.log_platform_event({
                "level": "INFO",
                "service": "thos-risk",
                "category": "risk_analysis",
                "action": "risk_snapshot_refreshed",
                "resource": source_version,
                "message": (
                    "Risk Analysis Agent refreshed the actionable-risk snapshot "
                    f"from {len(hunts)} hunt report(s) and "
                    f"{len(detections)} detection(s)."
                ),
                "context": {
                    "reason": reason,
                    "risk_count": len(result.get("items") or []),
                    "source_version": source_version,
                },
            })
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep prior snapshot readable
            await audit.fail_risk_refresh(source_version, str(exc), reason)
            logger.exception("risk snapshot refresh failed")
            return existing.get("payload") or {} if existing else {}


async def _risk_refresh_worker() -> None:
    global _risk_refresh_force
    while _risk_refresh_reasons:
        reasons = sorted(_risk_refresh_reasons)
        _risk_refresh_reasons.clear()
        force, _risk_refresh_force = _risk_refresh_force, False
        await _refresh_risk_snapshot(", ".join(reasons)[:500], force=force)


def _schedule_risk_refresh(reason: str, *, force: bool = False) -> None:
    """Coalesce frequent detection/report events into one background refresh."""
    global _risk_refresh_force, _risk_refresh_task
    _risk_refresh_reasons.add(str(reason or "evidence_changed")[:120])
    _risk_refresh_force = _risk_refresh_force or force
    if _risk_refresh_task is not None and not _risk_refresh_task.done():
        return
    task = asyncio.create_task(_risk_refresh_worker(), name="risk-snapshot-refresh")
    _risk_refresh_task = task
    _background_risk_refreshes.add(task)
    task.add_done_callback(_background_risk_done)


class _HuntSlot:
    """Reject a second hunt until the currently active hunt has completed."""

    async def __aenter__(self):
        global _active_hunt_count
        async with _active_hunt_lock:
            if _active_hunt_count:
                raise HTTPException(
                    status_code=409,
                    detail="A hunt is already running. Wait for it to complete before starting another hypothesis.",
                )
            _active_hunt_count += 1
        return self

    async def __aexit__(self, exc_type, exc, tb):
        global _active_hunt_count
        async with _active_hunt_lock:
            _active_hunt_count = max(0, _active_hunt_count - 1)
        return False


@app.on_event("shutdown")
async def _shutdown():
    # Cleanly tear down the shared MCP client session (see mcp_client.py)
    # and release pooled Postgres connections (see audit.py).
    pending = [
        *_background_hunts,
        *_background_forensics,
        *_background_risk_refreshes,
    ]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    await mcp_client.close()
    audit.close_pool()


@app.on_event("startup")
async def _ensure_agentic_schema():
    await audit.ensure_agentic_schema()
    await audit.reconcile_incomplete_hunts()
    await audit.reconcile_incomplete_forensic_cases()
    _schedule_risk_refresh("orchestrator_startup")


class HuntRequest(BaseModel):
    hunter_name: str = "anonymous"
    hypothesis_id: str | None = None
    hypothesis_text: str | None = None
    hypothesis_tactic: str = ""
    hypothesis_technique: str = ""
    siem_type: str = "folder"
    siem_types: list[str] = Field(default_factory=list, max_length=16)
    # Only used when siem_type == "folder": local directory containing
    # log artifacts (evtx/log/syslog/csv/CEF/JSON/ECS/xml/txt/pcap) to
    # hunt against instead of a live SIEM API.
    log_source_path: str | None = None
    max_iterations: int = Field(
        default_factory=lambda: max(1, min(5, int(get_value("general", "default_iterations", default=2)))),
        ge=1,
        le=5,
    )
    lookback_minutes: int | None = Field(default=None, ge=1, le=525600)
    max_lookback_minutes: int = Field(default=10080, ge=60, le=525600)
    # "1" = Executive cover page (plain-language, for management/compliance)
    # "2" = SOC Analyst cover panel (technique/tactic/ingestion-stats table)
    cover_style: str = "1"
    workload_class: str = Field(
        default="interactive", pattern="^(interactive|scheduled)$"
    )


class CaseCreateRequest(BaseModel):
    hunt_id: str | None = None
    title: str
    priority: str = "medium"
    assigned_to: str | None = None
    summary: str | None = None
    actor: str = "api-user"


class CaseUpdateRequest(BaseModel):
    status: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
    summary: str | None = None
    actor: str = "api-user"


class FeedbackRequest(BaseModel):
    hunt_id: str
    rating: str
    finding_ref: str | None = None
    correction: str | None = None
    analyst_name: str = "api-user"


class AuditEventRequest(BaseModel):
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    service: str = Field(default="thos-ui", min_length=1, max_length=120)
    category: str = Field(default="operation", min_length=1, max_length=120)
    actor: str = Field(default="", max_length=160)
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(default="", max_length=1000)
    status_code: int | None = Field(default=None, ge=100, le=599)
    duration_ms: int | None = Field(default=None, ge=0)
    message: str = Field(min_length=1, max_length=4000)
    context: dict = Field(default_factory=dict)


class RiskResolutionRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=160)
    role: str = Field(pattern="^(Admin|SME)$")
    note: str = Field(default="", max_length=1000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=16_000)
    conversation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    analyst: str = "analyst"
    role: str = Field(default="Expert", pattern="^(Admin|SME|Expert)$")
    permissions: list[str] = Field(default_factory=list, max_length=32)


class ChatConversationRequest(BaseModel):
    analyst: str = "analyst"
    title: str = Field(default="New conversation", max_length=120)


class ScheduledSigmaRequest(BaseModel):
    schedule_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(min_length=1, max_length=256)
    siem_type: str = Field(pattern="^(mock|folder|wazuh|logrhythm|splunk|qradar|elasticsearch)$")
    log_source_path: str | None = None


class ScheduledSigmaBatchRequest(BaseModel):
    schedule_id: str = Field(min_length=1, max_length=128)
    rule_ids: list[str] = Field(min_length=1, max_length=500)
    siem_type: str = Field(pattern="^wazuh$")


class YaraScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    recursive: bool = True
    rule_id: str | None = Field(default=None, max_length=256)
    modified_since: str | None = None
    analysis_profile: str = Field(
        default="evidence", pattern="^(evidence|memory)$",
    )


class ScheduledYaraRequest(YaraScanRequest):
    schedule_id: str = Field(min_length=1, max_length=128)


class ForensicAnalyzeRequest(BaseModel):
    case_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    case_title: str = Field(min_length=1, max_length=300)
    case_dir: str = Field(min_length=1, max_length=4096)
    examiner: str = Field(min_length=1, max_length=128)


class ForensicStaticScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    artifact_type: str = Field(
        default="suspicious_file",
        pattern="^(evidence|suspicious_file|memory_dump|process_dump)$",
    )


class LogSearchTranslateRequest(BaseModel):
    portable_query: str = Field(min_length=3, max_length=8_000)
    siem_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    lookback_minutes: int = Field(default=1440, ge=1, le=525_600)


class LogSearchRunRequest(LogSearchTranslateRequest):
    query: str = Field(min_length=1, max_length=8_000)
    limit: int = Field(default=250, ge=1, le=2_000)
    log_source_path: str | None = Field(default=None, max_length=4_096)


def _initial_state(hunt_id: str, req: HuntRequest) -> HuntState:
    sources = list(dict.fromkeys(
        str(source).strip().lower()
        for source in ([req.siem_type, *req.siem_types])
        if str(source).strip()
    )) or ["folder"]
    return {
        "hunt_id": hunt_id,
        "hunt_started_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hunter_name": req.hunter_name,
        "siem_type": req.siem_type,
        "siem_types": sources,
        "log_source_path": req.log_source_path,
        "hypothesis_id": req.hypothesis_id,
        "hypothesis_text": req.hypothesis_text or "",
        "hypothesis_tactic": req.hypothesis_tactic,
        "hypothesis_technique": req.hypothesis_technique,
        "logs": [],
        "query_plan": [],
        "pending_query_plan": [],
        "executed_query_keys": [],
        "retrieval_attempts": [],
        "source_diagnostics": {},
        "retrieval_exhausted": False,
        "hunt_completeness": {},
        "active_lookback_minutes": req.lookback_minutes,
        "iteration": 0,
        "max_iterations": req.max_iterations,
        "need_more_logs": False,
        "executed_queries": [],
        "max_reasoning_followups": max(0, MAX_REASONING_FOLLOWUPS),
        "adaptive_replans": 0,
        "max_adaptive_replans": max(
            1,
            int(
                os.environ.get(
                    "THOS_MAX_ADAPTIVE_REPLANS",
                    str(
                        get_value(
                            "autonomy", "max_adaptive_replans", default=8
                        )
                    ),
                )
            ),
        ),
        "replan_history": [],
        "replan_decision_owner": None,
        "zero_result_expansions": 0,
        "noise_refinements": 0,
        "max_lookback_minutes": req.max_lookback_minutes,
        "max_query_limit": max(
            1,
            int(
                os.environ.get(
                    "THOS_MAX_QUERY_LIMIT",
                    str(
                        get_value(
                            "autonomy", "max_query_limit", default=2000
                        )
                    ),
                )
            ),
        ),
        "enrichment": {},
        "cover_style": req.cover_style,
        "workload_class": req.workload_class,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/hypotheses", dependencies=[Depends(require_api_key)])
async def hypotheses(tactic: str = ""):
    """Proxy to the HEARTH hypothesis tool so the chat-ui doesn't need direct MCP access."""
    return await call_tool("list_hearth_hypotheses", {"tactic": tactic})


@app.get("/hypotheses/last-runs", dependencies=[Depends(require_api_key)])
async def hypothesis_last_runs():
    return await audit.hypothesis_last_runs()


@app.get("/hypotheses/duration-stats", dependencies=[Depends(require_api_key)])
async def hypothesis_duration_stats(limit_per_hypothesis: int = 30):
    return await audit.hypothesis_duration_statistics(limit_per_hypothesis)


@app.get("/dashboard/operations", dependencies=[Depends(require_api_key)])
async def operations_dashboard(hours: int = 24):
    return await audit.operations_dashboard(max(1, min(hours, 24 * 365)))


@app.get("/risks", dependencies=[Depends(require_api_key)])
async def actionable_risks(
    limit: int = 500,
    hours: int = 0,
    refresh: bool = False,
):
    bounded_limit = max(1, min(limit, 2000))
    bounded_hours = max(1, min(hours, 24 * 365 * 10)) if hours else 0
    snapshot = await audit.get_risk_snapshot()
    _schedule_risk_refresh(
        "manual_risk_refresh" if refresh else "risk_page_read",
        force=refresh,
    )
    payload = (
        snapshot.get("payload")
        if snapshot and isinstance(snapshot.get("payload"), dict)
        else {
            "generated_at": None,
            "agent": {
                "id": "risk_analysis",
                "name": "Risk Analysis Agent",
                "mode": "materialized model analysis",
                "degraded": False,
                "errors": [],
            },
            "summary": {},
            "items": [],
        }
    )
    payload = apply_risk_resolutions(
        payload, await audit.list_risk_resolutions()
    )
    result = filter_risk_payload(payload, bounded_limit, bounded_hours or None)
    return {
        **result,
        "materialized": True,
        "refresh": {
            "status": str(snapshot.get("status") or "pending")
            if snapshot else "pending",
            "reason": str(snapshot.get("refresh_reason") or "")
            if snapshot else "",
            "error": str(snapshot.get("error_msg") or "")
            if snapshot else "",
            "updated_at": snapshot.get("updated_at") if snapshot else None,
        },
    }


@app.patch("/risks/{risk_id}/resolve", dependencies=[Depends(require_api_key)])
async def resolve_actionable_risk(
    risk_id: str,
    request: RiskResolutionRequest,
):
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", risk_id):
        raise HTTPException(status_code=422, detail="Invalid risk identifier")
    snapshot = await audit.get_risk_snapshot()
    items = ((snapshot or {}).get("payload") or {}).get("items") or []
    if not any(str(item.get("id") or "") == risk_id for item in items if isinstance(item, dict)):
        raise HTTPException(status_code=404, detail="Risk not found")
    resolution = await audit.resolve_risk(risk_id, request.actor, request.note)
    await audit.log_platform_event({
        "service": "thos-risk",
        "category": "risk_management",
        "actor": request.actor,
        "action": "risk_resolved",
        "resource": risk_id,
        "message": f"Risk {risk_id} was marked resolved and made inactive",
        "context": {"role": request.role, "note": request.note},
    })
    return {**resolution, "active": False}


@app.post("/audit/events", dependencies=[Depends(require_api_key)], status_code=202)
async def record_audit_event(request: AuditEventRequest):
    await audit.log_platform_event(request.model_dump())
    return {"recorded": True}


@app.get("/log-search/context/{siem_type}", dependencies=[Depends(require_api_key)])
async def log_search_context(siem_type: str):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", siem_type):
        raise HTTPException(status_code=422, detail="invalid telemetry source")
    mapping, schema = await asyncio.gather(
        call_tool("siem_field_mapping", {"siem_type": siem_type}),
        call_tool("get_cached_siem_schema", {"siem_type": siem_type}),
    )
    normalized_mapping = mapping if isinstance(mapping, dict) else {}
    field_rows = schema.get("fields") if isinstance(schema, dict) else []
    return {
        "siem_type": siem_type,
        "field_mapping": {
            str(key): str(value)
            for key, value in normalized_mapping.items()
            if key != "available_fields" and str(value).strip()
        },
        "schema": {
            "fields": field_rows[:500] if isinstance(field_rows, list) else [],
            "field_count": int(schema.get("field_count") or 0)
            if isinstance(schema, dict) else 0,
            "last_verified": schema.get("last_verified")
            if isinstance(schema, dict) else None,
            "stale": bool(schema.get("stale", True))
            if isinstance(schema, dict) else True,
        },
    }


@app.post("/log-search/translate", dependencies=[Depends(require_api_key)])
async def translate_log_search(request: LogSearchTranslateRequest):
    result = await call_tool("generate_siem_query", {
        "hypothesis_text": request.portable_query,
        "siem_type": request.siem_type,
        "objective": (
            "Translate the analyst-authored portable correlation query into "
            "one bounded, read-only target-SIEM query. Preserve its literal "
            "values and boolean intent, and use only mapped available fields."
        ),
        "investigation_context": {
            "manual_log_search": True,
            "lookback_minutes": request.lookback_minutes,
        },
    })
    if not isinstance(result, dict) or not str(result.get("query") or "").strip():
        detail = (
            result.get("query_validation_error")
            if isinstance(result, dict) else ""
        ) or "Could not translate the portable query into validated SIEM syntax"
        raise HTTPException(status_code=422, detail=str(detail))
    return {
        "siem_type": request.siem_type,
        "portable_query": request.portable_query,
        "query": result["query"],
        "generation_mode": result.get("query_generation_mode", "model"),
        "warnings": result.get("query_generation_warnings") or [],
        "lookback_minutes": request.lookback_minutes,
    }


@app.post("/log-search/run", dependencies=[Depends(require_api_key)])
async def run_log_search(request: LogSearchRunRequest):
    validation = await call_tool("validate_siem_query", {
        "query": request.query,
        "portable_query": request.portable_query,
        "siem_type": request.siem_type,
    })
    if not isinstance(validation, dict) or validation.get("validation_error"):
        raise HTTPException(
            status_code=422,
            detail=str(
                validation.get("validation_error")
                if isinstance(validation, dict)
                else "Query validation failed"
            ),
        )
    normalized_query = str(validation.get("query") or "").strip()
    if not normalized_query:
        raise HTTPException(status_code=422, detail="Query validation returned no executable query")
    started = time.perf_counter()
    result = await call_tool("fetch_siem_logs", {
        "query": normalized_query,
        "limit": request.limit,
        "siem_type": request.siem_type,
        "log_source_path": request.log_source_path or "",
        "bypass_cache": True,
        "lookback_minutes": request.lookback_minutes,
    })
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="Telemetry source returned an invalid response")
    if result.get("error"):
        raise HTTPException(status_code=422, detail=str(result["error"]))
    logs = [item for item in result.get("logs") or [] if isinstance(item, dict)]
    return {
        **result,
        "siem_type": request.siem_type,
        "query": normalized_query,
        "logs": logs[:request.limit],
        "record_count": len(logs[:request.limit]),
        "lookback_minutes": request.lookback_minutes,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "executed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


@app.get("/audit/logs", dependencies=[Depends(require_api_key)])
async def platform_audit_logs(
    hours: int = 24,
    limit: int = 500,
    level: str = "all",
    query: str = "",
):
    if level.lower() not in {"all", "debug", "info", "warning", "error"}:
        raise HTTPException(status_code=422, detail="invalid log level")
    return await audit.list_platform_audit_logs(
        hours=max(1, min(hours, 24 * 365)),
        limit=max(1, min(limit, 2000)),
        level=level,
        query=query,
    )


@app.get("/hunts", dependencies=[Depends(require_api_key)])
async def hunt_history(limit: int = 100):
    return await audit.list_hunts(limit)


@app.delete("/hunts", dependencies=[Depends(require_api_key)])
async def clear_hunt_history():
    status = await audit.active_hunt_status()
    if status.get("active"):
        raise HTTPException(status_code=409, detail="Hunt history cannot be cleared while a hunt is running")
    return await audit.clear_hunt_history()


@app.get("/hunts/{hunt_id}/progress", dependencies=[Depends(require_api_key)])
async def hunt_progress(hunt_id: str):
    progress = await audit.hunt_progress(hunt_id=hunt_id)
    if progress is None:
        raise HTTPException(status_code=404, detail="hunt not found")
    if progress.get("current_stage"):
        progress["current_agent"] = _agent_stage(progress["current_stage"])
    return progress


@app.get("/hunt/status", dependencies=[Depends(require_api_key)])
async def hunt_status():
    active = _active_hunt_count > 0
    progress = await audit.hunt_progress(active_only=True) if active else None
    if progress and progress.get("current_stage"):
        progress["current_agent"] = _agent_stage(progress["current_stage"])
    return {"active": active, "active_count": _active_hunt_count, "hunt": progress}


async def _run_forensic_background(request: ForensicAnalyzeRequest) -> None:
    from services.forensics.workflow import run_forensic_case

    async def progress(event: dict) -> None:
        if event.get("event") == "agent_started":
            await audit.forensic_stage_started(request.case_id, str(event.get("stage", "")))
        elif event.get("event") == "agent_complete":
            await audit.log_forensic_step(request.case_id, event)

    try:
        async with _forensic_worker_slot:
            result = await run_forensic_case(request.case_dir, progress)
        await audit.complete_forensic_case(
            request.case_id,
            "completed",
            report_path=str(result.get("report_path") or ""),
            summary=str(result.get("summary") or ""),
        )
    except asyncio.CancelledError:
        await asyncio.shield(audit.complete_forensic_case(
            request.case_id, "failed", error_msg="Forensic analysis was interrupted during shutdown.",
        ))
        raise
    except Exception as exc:  # noqa: BLE001 - persist a terminal case state
        logger.exception("forensic analysis failed", extra={"case_id": request.case_id})
        await audit.complete_forensic_case(request.case_id, "failed", error_msg=str(exc))


@app.post("/forensics/analyze", dependencies=[Depends(require_api_key)], status_code=202)
async def start_forensic_analysis(request: ForensicAnalyzeRequest):
    try:
        uuid.UUID(request.case_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="case_id must be a UUID") from exc
    async with _forensic_start_lock:
        created = await audit.create_forensic_case(
            request.case_id, request.case_title.strip(), request.examiner.strip(), request.case_dir,
        )
        if created is None:
            existing = await audit.get_forensic_case(request.case_id)
            if existing is not None:
                raise HTTPException(status_code=409, detail="forensic case already exists")
            raise HTTPException(status_code=503, detail="forensic case store is unavailable")
        task = asyncio.create_task(_run_forensic_background(request))
        _background_forensics.add(task)
        task.add_done_callback(_background_forensic_done)
    return created


@app.get("/forensics", dependencies=[Depends(require_api_key)])
async def forensic_cases(limit: int = 100):
    return await audit.list_forensic_cases(limit)


@app.get("/forensics/tools", dependencies=[Depends(require_api_key)])
async def forensic_tools():
    from services.forensics.tools import tool_status

    return await asyncio.to_thread(tool_status)


@app.post("/forensics/static-scan", dependencies=[Depends(require_api_key)])
async def forensic_static_scan(request: ForensicStaticScanRequest):
    from services.forensics.analysis import sha256_file
    from services.forensics.planner import plan_forensic_tools
    from services.forensics.tools import run_static_triage

    root = Path(os.environ.get("FORENSIC_ROOT", "/data/log_sources/forensic")).resolve()
    target = Path(request.path).resolve()
    if not target.is_file() or root not in target.parents:
        raise HTTPException(
            status_code=422,
            detail="forensic artifact path is outside the managed evidence root",
        )
    actual_hash = await asyncio.to_thread(sha256_file, target)
    if not secrets.compare_digest(actual_hash.lower(), request.sha256.lower()):
        raise HTTPException(status_code=409, detail="forensic artifact integrity mismatch")
    derived = target.parent / "_thos_derived"
    derived.mkdir(mode=0o750, exist_ok=True)
    evidence_id = f"static-{actual_hash[:16]}"
    verified = {
        "case_id": evidence_id,
        "case_dir": str(target.parent),
        "evidence": [{
            "evidence_id": evidence_id,
            "original_name": target.name,
            "stored_name": target.name,
            "path": str(target),
            "size_bytes": target.stat().st_size,
            "sha256": actual_hash,
            "artifact_type": request.artifact_type,
        }],
    }
    plan = await plan_forensic_tools(verified)
    artifact_plan = next(
        (
            item.get("tools") or []
            for item in plan.get("artifacts") or []
            if item.get("evidence_id") == evidence_id
        ),
        [],
    )
    return await asyncio.to_thread(
        run_static_triage,
        target,
        sha256=actual_hash,
        artifact_type=request.artifact_type,
        derived_dir=derived,
        tool_plan=artifact_plan,
    )


@app.get("/forensics/{case_id}", dependencies=[Depends(require_api_key)])
async def forensic_case(case_id: str):
    result = await audit.get_forensic_case(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="forensic case not found")
    return result


@app.get("/sigma/detections", dependencies=[Depends(require_api_key)])
async def scheduled_sigma_detections(limit: int = 100):
    return await audit.list_sigma_detections(limit)


@app.post("/sigma/detections/{run_id}/analysis", dependencies=[Depends(require_api_key)])
async def analyze_scheduled_sigma_detection(run_id: str):
    try:
        uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid detection run identifier") from exc
    detection = await audit.get_sigma_detection(run_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="scheduled detection not found")
    cached = (detection.get("analysis") or {}).get("ai_analysis")
    if isinstance(cached, dict) and cached.get("analysis_lines"):
        return {**cached, "cached": True}
    result = await analyze_detection(detection)
    if result.get("generation_mode") != "local_model":
        raise HTTPException(
            status_code=503,
            detail=result.get("error") or "detection analysis model unavailable",
        )
    saved = await audit.save_sigma_ai_analysis(run_id, result)
    if saved is None:
        raise HTTPException(status_code=503, detail="could not persist detection analysis")
    _schedule_risk_refresh(f"detection_analysis:{run_id}")
    return {**result, "cached": False}


@app.post("/siem/schema/{siem_type}/discover", dependencies=[Depends(require_api_key)])
async def discover_siem_schema(siem_type: str, sample_limit: int = 50):
    if siem_type not in {"mock", "folder", "wazuh", "logrhythm", "splunk", "qradar", "elasticsearch"}:
        raise HTTPException(status_code=404, detail="unsupported SIEM")
    try:
        return await call_tool("discover_siem_fields", {
            "siem_type": siem_type,
            "sample_limit": max(1, min(sample_limit, 200)),
            "log_source_path": os.environ.get("LOG_SOURCE_DIR", "/data/log_sources")
            if siem_type == "folder" else "",
        })
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/sigma/compile/{siem_type}", dependencies=[Depends(require_api_key)])
async def compile_sigma_catalog_for_siem(siem_type: str):
    if siem_type not in {"wazuh", "splunk", "qradar", "logrhythm"}:
        raise HTTPException(status_code=404, detail="unsupported SIEM")
    try:
        return await call_tool("compile_sigma_rules_for_siem", {"siem_type": siem_type})
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/sigma/scheduled/run", dependencies=[Depends(require_api_key)])
async def run_scheduled_sigma(request: ScheduledSigmaRequest):
    from services.detection.sigma_detection_agent import run_scheduled_sigma_detection
    try:
        result = await run_scheduled_sigma_detection(
            schedule_id=request.schedule_id,
            rule_id=request.rule_id,
            siem_type=request.siem_type,
            log_source_path=request.log_source_path,
        )
        if result.get("status") == "detected" and result.get("events_matched", 0):
            triage = (result.get("analysis") or {}).get("triage") or {}
            case = await audit.create_case(
                None,
                f"Scheduled detection: {result.get('rule_title') or result.get('rule_id')}",
                str(triage.get("priority") or "medium"),
                None,
                str(triage.get("note") or result.get("analysis", {}).get("summary") or ""),
                "scheduled-detection-agent",
            )
            if case:
                result["case_id"] = str(case["case_id"])
        stored = await audit.log_sigma_detection(result)
        if int(result.get("events_matched") or 0) > 0:
            _schedule_risk_refresh(
                f"detection_completed:{result.get('rule_id') or request.rule_id}"
            )
        return stored or result
    except Exception as exc:  # noqa: BLE001 - persist a failed scheduled execution
        await audit.log_sigma_detection({
            "schedule_id": request.schedule_id,
            "rule_id": request.rule_id,
            "rule_title": request.rule_id,
            "rule_source": "unknown",
            "level": "unknown",
            "siem_type": request.siem_type,
            "status": "failed",
            "events_matched": 0,
            "matched_events": [],
            "analysis": {},
            "error": str(exc),
        })
        logger.exception("scheduled detection-rule execution failed")
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/sigma/scheduled/run-batch", dependencies=[Depends(require_api_key)])
async def run_scheduled_sigma_batch(request: ScheduledSigmaBatchRequest):
    from services.detection.sigma_detection_agent import (
        run_scheduled_sigma_batch as execute_batch,
    )

    results = await execute_batch(
        schedule_id=request.schedule_id,
        rule_ids=request.rule_ids,
        siem_type=request.siem_type,
    )
    stored_results = []
    for result in results:
        if result.get("status") == "detected" and result.get("events_matched", 0):
            triage = (result.get("analysis") or {}).get("triage") or {}
            case = await audit.create_case(
                None,
                f"Scheduled detection: {result.get('rule_title') or result.get('rule_id')}",
                str(triage.get("priority") or "medium"),
                None,
                str(triage.get("note") or result.get("analysis", {}).get("summary") or ""),
                "scheduled-detection-agent",
            )
            if case:
                result["case_id"] = str(case["case_id"])
        stored = await audit.log_sigma_detection(result)
        stored_results.append(stored or result)
    if any(int(item.get("events_matched") or 0) > 0 for item in results):
        _schedule_risk_refresh(f"detection_batch_completed:{request.schedule_id}")
    return {
        "execution_mode": "wazuh_msearch",
        "rules_submitted": len(request.rule_ids),
        "results": stored_results,
    }


@app.get("/sigma/catalog/ready", dependencies=[Depends(require_api_key)])
async def ready_sigma_rules(siem_type: str):
    """Return the current schema-compatible rule IDs for bounded batch scheduling."""
    from services.detection.sigma_query_catalog import ready_rule_ids

    if siem_type not in {"wazuh", "splunk"}:
        raise HTTPException(
            status_code=422,
            detail="Bulk detection-rule scheduling requires a precompiled Wazuh or Splunk backend",
        )
    rule_ids = ready_rule_ids(siem_type)
    return {"siem_type": siem_type, "rule_ids": rule_ids, "count": len(rule_ids)}


@app.post("/siem/test/{siem_type}", dependencies=[Depends(require_api_key)])
async def test_siem_connection(siem_type: str):
    queries = {
        "mock": "*",
        "folder": "*",
        "wazuh": '{"query":{"match_all":{}}}',
        "logrhythm": "*",
        "splunk": "search * | head 1",
        "qradar": "SELECT * FROM events LAST 5 MINUTES",
        "elasticsearch": '{"query":{"match_all":{}}}',
    }
    if siem_type not in queries:
        raise HTTPException(status_code=404, detail="unsupported SIEM")
    result = await call_tool("fetch_siem_logs", {"query": queries[siem_type], "limit": 1, "siem_type": siem_type})
    if result.get("error"):
        raise HTTPException(status_code=422, detail=result["error"])
    return {"status": "connected", "siem_type": siem_type, "record_count": result.get("record_count", 0)}


def _managed_yara_targets(value: str, recursive: bool,
                          modified_since: str | None = None) -> list[str]:
    candidate = Path(value).resolve()
    allowed_roots = [
        Path(os.environ.get("LOG_SOURCE_DIR", "/data/log_sources")).resolve(),
        Path(os.environ.get("FORENSIC_ROOT", "/data/log_sources/forensic")).resolve(),
    ]
    if not any(candidate == root or root in candidate.parents for root in allowed_roots):
        raise HTTPException(status_code=422, detail="YARA target is outside managed evidence roots")
    cutoff = None
    if modified_since:
        try:
            cutoff = datetime.fromisoformat(modified_since).timestamp()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="modified_since must be ISO-8601") from exc
    if candidate.is_file():
        return [str(candidate)] if cutoff is None or candidate.stat().st_mtime > cutoff else []
    if not candidate.is_dir():
        raise HTTPException(status_code=404, detail="YARA target does not exist")
    iterator = candidate.rglob("*") if recursive else candidate.glob("*")
    return [
        str(path) for path in iterator
        if path.is_file() and (cutoff is None or path.stat().st_mtime > cutoff)
    ][:1_000]


@app.post("/yara/scan", dependencies=[Depends(require_api_key)])
async def run_yara_scan(request: YaraScanRequest):
    from services.detection.yara_engine import scan_paths

    targets = _managed_yara_targets(
        request.path, request.recursive, request.modified_since,
    )
    memory_profile = request.analysis_profile == "memory"
    max_file_bytes = int(os.environ.get(
        "YARA_MEMORY_MAX_FILE_BYTES" if memory_profile else "YARA_MAX_FILE_BYTES",
        str(20 * 1024 * 1024 * 1024) if memory_profile else str(256 * 1024 * 1024),
    ))
    timeout_seconds = int(os.environ.get(
        "YARA_MEMORY_SCAN_TIMEOUT_SECONDS" if memory_profile else "YARA_SCAN_TIMEOUT_SECONDS",
        "600" if memory_profile else "30",
    ))
    started_at = time.perf_counter()
    result = await asyncio.to_thread(
        scan_paths,
        targets,
        {request.rule_id} if request.rule_id else None,
        max_file_bytes=max_file_bytes,
        timeout_seconds=timeout_seconds,
    )
    duration_ms = int((time.perf_counter() - started_at) * 1000)
    return {
        **result,
        "duration_ms": duration_ms,
        "files_scanned": len(targets),
        "modified_since": request.modified_since,
        "analysis_profile": request.analysis_profile,
        "scan_limit_bytes": max_file_bytes,
        "scan_timeout_seconds": timeout_seconds,
        "files_per_second": round(
            len(targets) / max(duration_ms / 1000, 0.001), 3
        ),
    }


@app.post("/yara/scheduled/run", dependencies=[Depends(require_api_key)])
async def run_scheduled_yara(request: ScheduledYaraRequest):
    result = await run_yara_scan(request)
    return {
        **result,
        "schedule_id": request.schedule_id,
        "rule_id": request.rule_id or "__all_enabled__",
        "status": "detected" if result.get("match_count") else "completed",
    }


_NEXT_PIPELINE_NODE = {
    "refresh_hearth_kb": "hypothesis", "hypothesis": "hunt_memory",
    "hunt_memory": "supervisor", "supervisor": "query_gen",
    "query_gen": "siem_fetch", "siem_fetch": "log_processing",
    "log_processing": "guardrail", "guardrail": "soc_tools",
    "soc_tools": "coverage_gap", "coverage_gap": "threat_intel",
    "threat_intel": "adaptive_replan",
    "adaptive_replan": "negative_screening_gate",
    "negative_screening_gate": "reasoning",
    "verifier": "detection_engineering",
    "detection_engineering": "communication", "communication": "report",
}


def _next_pipeline_node(completed_node: str, state: dict) -> str | None:
    if completed_node == "adaptive_replan":
        from services.orchestration.graph import route_after_adaptive_replan
        return route_after_adaptive_replan(state)
    if completed_node == "negative_screening_gate":
        from services.orchestration.graph import route_after_negative_screening
        route = route_after_negative_screening(state)
        return None if route == "no_evidence" else "reasoning"
    if completed_node == "reasoning":
        from services.orchestration.graph import route_after_reasoning
        route = route_after_reasoning(state)
        return None if route == "failed" else route
    return _NEXT_PIPELINE_NODE.get(completed_node)


def _agent_stage(node_name: str) -> dict:
    spec = agent_by_graph_node(node_name)
    stage = {
        "agent_id": spec.id if spec else node_name,
        "agent_name": spec.name if spec else node_name.replace("_", " ").title(),
        "activity": spec.purpose if spec else "Processes the current hunt stage.",
        "model_tier": None,
        "model_name": None,
    }
    if spec and spec.model_route:
        target = target_for(spec.model_route)
        stage.update({"model_tier": target.tier, "model_name": target.model})
    return stage


@app.post("/chat", dependencies=[Depends(require_api_key)])
async def chat_with_model(request: ChatRequest):
    from services.chat_agent import chat
    from services.memory import chat_memory
    conversation = None
    try:
        if request.conversation_id:
            conversation = await asyncio.to_thread(
                chat_memory.get_conversation, request.analyst, request.conversation_id,
            )
            if conversation is None:
                raise HTTPException(status_code=404, detail="Chat conversation expired or was not found")
        else:
            conversation = await asyncio.to_thread(chat_memory.create_conversation, request.analyst)
        history = list(conversation.get("messages", []))
        conversation = await asyncio.to_thread(
            chat_memory.append_message,
            request.analyst,
            conversation["id"],
            {"role": "user", "content": request.message},
        )
        result = await chat(
            request.message,
            history,
            request.analyst,
            role=request.role,
            permissions=request.permissions,
        )
        answer = str(result.get("answer", "")).strip()
        if not answer:
            raise RuntimeError("chat completed without an answer")
        conversation = await asyncio.to_thread(
            chat_memory.append_message,
            request.analyst,
            conversation["id"],
            {
                "role": "assistant",
                "content": answer,
                "tools": result.get("tools_used", []),
                "sources": result.get("knowledge_sources", []),
                "agents": result.get("delegated_agents", []),
            },
        )
        return {
            **result,
            "conversation_id": conversation["id"],
            "title": conversation["title"],
            "messages": conversation["messages"],
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        if conversation is not None:
            try:
                await asyncio.to_thread(
                    chat_memory.append_message,
                    request.analyst,
                    conversation["id"],
                    {"role": "assistant", "content": f"Chat could not complete: {exc}", "error": True},
                )
            except Exception:
                pass
        logger.exception("MCP-backed chat failed")
        raise HTTPException(status_code=502, detail=f"The local model chat failed: {exc}") from exc


@app.get("/chat/conversations", dependencies=[Depends(require_api_key)])
async def chat_conversations(analyst: str = "analyst"):
    from services.memory import chat_memory
    return await asyncio.to_thread(chat_memory.list_conversations, analyst)


@app.post("/chat/conversations", dependencies=[Depends(require_api_key)])
async def create_chat_conversation(request: ChatConversationRequest):
    from services.memory import chat_memory
    return await asyncio.to_thread(chat_memory.create_conversation, request.analyst, request.title)


@app.get("/chat/conversations/{conversation_id}", dependencies=[Depends(require_api_key)])
async def get_chat_conversation(conversation_id: str, analyst: str = "analyst"):
    from services.memory import chat_memory
    conversation = await asyncio.to_thread(chat_memory.get_conversation, analyst, conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Chat conversation expired or was not found")
    return conversation


@app.delete("/chat/conversations/{conversation_id}", dependencies=[Depends(require_api_key)])
async def delete_chat_conversation(conversation_id: str, analyst: str = "analyst"):
    from services.memory import chat_memory
    return {"deleted": await asyncio.to_thread(chat_memory.delete_conversation, analyst, conversation_id)}


@app.get("/log_sources", dependencies=[Depends(require_api_key)])
async def log_sources(folder: str):
    """Proxy to the folder-listing tool so the chat-ui can show what log
    files are sitting in a candidate folder before running a hunt against it."""
    return await call_tool("list_log_source_files", {"folder": folder})


# --- Custom Knowledge Base (analyst-uploaded documents) ------------------
# AnythingLLM-style: drop in files, they're chunked + embedded, and become
# semantically searchable. All four endpoints are thin proxies to the
# corresponding MCP tools in services/api/server.py, same pattern as
# /hypotheses and /log_sources above.

# Per-upload cap mirrors services/knowledge/custom_kb.MAX_DOCUMENT_BYTES;
# kept here too so an oversized upload is rejected before it's even
# base64-encoded and shipped over MCP.
KB_MAX_UPLOAD_BYTES = int(os.environ.get("KB_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))


@app.post("/kb/upload", dependencies=[Depends(require_api_key)])
async def kb_upload(file: UploadFile = File(...)):
    """Ingest one uploaded document into the custom knowledge base."""
    content = await file.read()
    if len(content) > KB_MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"'{file.filename}' exceeds the {KB_MAX_UPLOAD_BYTES}-byte upload limit",
        )
    content_b64 = base64.b64encode(content).decode("ascii")
    return await call_tool("upload_kb_document", {"filename": file.filename, "content_b64": content_b64})


@app.get("/kb/documents", dependencies=[Depends(require_api_key)])
async def kb_documents():
    """List every document currently ingested into the custom knowledge base."""
    return await call_tool("list_kb_documents", {})


@app.delete("/kb/documents/{doc_id}", dependencies=[Depends(require_api_key)])
async def kb_delete_document(doc_id: str):
    """Remove a document (all its chunks) from the custom knowledge base."""
    return await call_tool("delete_kb_document", {"doc_id": doc_id})


@app.get("/kb/search", dependencies=[Depends(require_api_key)])
async def kb_search(query: str, n_results: int = 5):
    """Semantic search over the custom knowledge base."""
    return await call_tool("search_knowledge_base", {"query": query, "n_results": n_results})


@app.post("/hypotheses/refresh", dependencies=[Depends(require_api_key)])
async def refresh_hypotheses():
    """Manually trigger a live re-fetch of HEARTH hypotheses from GitHub,
    bypassing the per-hunt Redis TTL gate used by the graph's
    refresh_hearth_kb node. Useful right after THOR Collective publishes
    new hypotheses, without waiting for the TTL to expire or running a
    full hunt."""
    return await call_tool("refresh_hearth_hypotheses", {})


_CASE_STATUSES = {"open", "in_progress", "resolved", "closed"}
_PRIORITIES = {"low", "medium", "high", "critical"}
_FEEDBACK_RATINGS = {"up", "down", "corrected"}


@app.get("/cases", dependencies=[Depends(require_api_key)])
async def cases(status: str | None = None, limit: int = 100):
    if status and status not in _CASE_STATUSES:
        raise HTTPException(status_code=422, detail="invalid case status")
    return await audit.list_cases(status, max(1, min(limit, 200)))


@app.post("/cases", dependencies=[Depends(require_api_key)], status_code=201)
async def create_case(request: CaseCreateRequest):
    if not request.title.strip() or len(request.title) > 500:
        raise HTTPException(status_code=422, detail="title must contain 1-500 characters")
    if request.priority not in _PRIORITIES:
        raise HTTPException(status_code=422, detail="invalid case priority")
    result = await audit.create_case(request.hunt_id, request.title.strip(), request.priority,
                                     request.assigned_to, request.summary, request.actor)
    if result is None:
        raise HTTPException(status_code=503, detail="case store unavailable or referenced hunt does not exist")
    return result


@app.patch("/cases/{case_id}", dependencies=[Depends(require_api_key)])
async def update_case(case_id: str, request: CaseUpdateRequest):
    if request.status and request.status not in _CASE_STATUSES:
        raise HTTPException(status_code=422, detail="invalid case status")
    if request.priority and request.priority not in _PRIORITIES:
        raise HTTPException(status_code=422, detail="invalid case priority")
    result = await audit.update_case(case_id, request.status, request.priority,
                                     request.assigned_to, request.summary, request.actor)
    if result is None:
        raise HTTPException(status_code=404, detail="case not found or case store unavailable")
    return result


@app.post("/feedback", dependencies=[Depends(require_api_key)], status_code=201)
async def capture_feedback(request: FeedbackRequest):
    if request.rating not in _FEEDBACK_RATINGS:
        raise HTTPException(status_code=422, detail="rating must be up, down, or corrected")
    result = await audit.record_feedback(request.hunt_id, request.finding_ref, request.rating,
                                         request.correction, request.analyst_name)
    if result is None:
        raise HTTPException(status_code=503, detail="feedback store unavailable or hunt does not exist")
    return result


@app.get("/learning/feedback-export", dependencies=[Depends(require_api_key)])
async def learning_feedback_export(limit: int = 5000):
    """Export analyst-labelled examples for offline, on-prem evaluation/fine-tuning."""
    return await audit.export_learning_feedback(max(1, min(limit, 5000)))


@app.get("/hunts/{hunt_id}/metrics", dependencies=[Depends(require_api_key)])
async def get_hunt_metrics(hunt_id: str):
    return await audit.hunt_metrics(hunt_id)


async def _create_review_artifacts(hunt_id: str, final_state: dict, owner: str) -> None:
    """Persist a case when deterministic verification requires analyst review."""
    if not final_state.get("analyst_review_required"):
        return
    if final_state.get("case_id"):
        return
    case = await audit.create_case(
        hunt_id, f"Analyst review required: {final_state.get('technique_name') or 'THOS hunt'}",
        "high", owner, final_state.get("reasoning_summary"), "thos-verifier",
    )
    if case:
        final_state["case_id"] = str(case["case_id"])


def _audit_outcome(state: dict) -> dict:
    enrichment = state.get("enrichment") or {}
    verifier = state.get("verifier_result") or {}
    return {
        "report_status": state.get("report_status"),
        "report_path": state.get("report_path"),
        "reasoning_mode": state.get("reasoning_mode"),
        "reasoning_degraded": bool(state.get("reasoning_degraded")),
        "reasoning_attempts": state.get("reasoning_attempts", 0),
        "reasoning_error": state.get("reasoning_error"),
        "reasoning_skip_reason": state.get("reasoning_skip_reason"),
        "related_technique_signals": state.get("related_technique_signals") or [],
        "verification_status": verifier.get("status"),
        "verification_checked_citations": verifier.get(
            "checked_citations", 0
        ),
        "verification_invalid_references": verifier.get(
            "invalid_references", []
        ),
        "hunt_completeness": state.get("hunt_completeness") or {},
        "retrieval_attempt_count": len(state.get("retrieval_attempts") or []),
        "source_diagnostics": state.get("source_diagnostics") or {},
        "selected_sources": state.get("siem_types") or [state.get("siem_type")],
        "sigmahq_rules_evaluated": enrichment.get("sigmahq_rules_evaluated", 0),
        "sigma_rules_evaluated": enrichment.get("sigma_rules_evaluated", 0),
        "records_analyzed": len(state.get("processed_logs") or []),
    }


@app.post("/hunt", dependencies=[Depends(require_api_key)])
async def run_hunt(req: HuntRequest):
    """Run a full hunt (hypothesis -> query -> fetch -> process -> SOC tools
    -> reasoning -> [loop] -> report) and return the final state."""
    await _enforce_hunt_rate_limit(req.hunter_name)
    hunt_id = str(uuid.uuid4())
    state = _initial_state(hunt_id, req)
    final_state = dict(state)

    # Binds hunt_id/hunter_name onto every log line emitted anywhere in
    # this request's async context from here on -- this module, graph
    # nodes, mcp_client, audit, retry -- without threading hunt_id
    # through every call site by hand. Reset in `finally` so the next
    # request handled by this worker (or logging done outside any hunt)
    # doesn't inherit a stale hunt_id.
    ctx_tokens = set_hunt_context(hunt_id, req.hunter_name)
    workload_token = set_model_workload(req.workload_class)
    try:
        logger.info("hunt started", extra={"hypothesis_id": req.hypothesis_id, "siem_type": req.siem_type})

        async with _HuntSlot():
            await audit.log_hunt_start(hunt_id, req.hunter_name, req.hypothesis_id, req.hypothesis_text)

            last_step_at = time.perf_counter()
            try:
                async for step in compiled_graph.astream(state, stream_mode="updates"):
                    for node_name, partial in step.items():
                        duration_ms = int((time.perf_counter() - last_step_at) * 1000)
                        last_step_at = time.perf_counter()
                        if partial is None:
                            # LangGraph uses None for a successful node with no
                            # state mutation (for example a no-op KB refresh).
                            partial = {}
                        final_state.update(partial)
                        stage = _agent_stage(node_name)
                        await audit.log_hunt_step(
                            hunt_id, node_name, partial, duration_ms,
                            stage["agent_name"], stage["model_tier"], stage["model_name"],
                        )
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error("graph error", exc_info=True, extra={"node": "graph"})
                await audit.log_tool_error(hunt_id, "graph", tb)
                await audit.log_hunt_complete(
                    hunt_id, "failed", "graph", str(e), _audit_outcome(final_state),
                )
                return {"hunt_id": hunt_id, "error": str(e), "state": final_state}

            if final_state.get("reasoning_failed") or final_state.get("verification_failed"):
                stage = "reasoning" if final_state.get("reasoning_failed") else "verifier"
                failure = final_state.get("error") or f"{stage} failed"
                await audit.log_tool_error(
                    hunt_id,
                    stage,
                    failure,
                    {"attempts": final_state.get("reasoning_attempts", 3)},
                )
                await audit.log_hunt_complete(
                    hunt_id, "failed", stage, failure, _audit_outcome(final_state),
                )
                logger.error("hunt stopped without report: %s", failure, extra={"node": stage})
                return final_state

            await audit.log_hunt_complete(
                hunt_id, "completed", outcome=_audit_outcome(final_state),
            )
            await _create_review_artifacts(hunt_id, final_state, req.hunter_name)
            if final_state.get("report_path"):
                await audit.log_report(hunt_id, final_state["report_path"], final_state.get("reasoning_summary", ""))
                _schedule_risk_refresh(f"hunt_report_generated:{hunt_id}")

            logger.info("hunt completed")
            return final_state
    except asyncio.CancelledError:
        interruption = "Synchronous hunt request was interrupted before a terminal event."
        await asyncio.shield(audit.log_tool_error(hunt_id, "request", interruption))
        await asyncio.shield(audit.log_hunt_complete(
            hunt_id, "failed", "request", interruption, _audit_outcome(final_state),
        ))
        raise
    finally:
        reset_model_workload(workload_token)
        reset_hunt_context(ctx_tokens)


@app.post("/hunt/stream", dependencies=[Depends(require_api_key)])
async def run_hunt_stream(req: HuntRequest):
    """Same as /hunt but streams one JSON line per completed node, so a chat
    UI can show live progress (e.g. 'fetching logs...', 'reasoning...')."""
    await _enforce_hunt_rate_limit(req.hunter_name)
    hunt_id = str(uuid.uuid4())
    state = _initial_state(hunt_id, req)

    # Bound here (not inside event_gen) purely so the "hunt started" log
    # line and the audit.log_hunt_start call below carry hunt_id. This
    # token is intentionally never reset explicitly -- it lives in this
    # request-handling coroutine's own context, which is discarded once
    # this function returns, no different than any other request-scoped
    # contextvars.Token going out of scope.
    #
    # It CANNOT be reused for reset_hunt_context() inside event_gen()'s
    # finally block: Starlette's StreamingResponse iterates body_iterator
    # (event_gen) inside a separately spawned task (see
    # starlette.responses.stream_response / anyio's task group), which
    # gets its own COPY of this context. contextvars.Token.reset() must
    # be called in the exact Context object where set() happened, so
    # calling it from that copied task context raises:
    #   ValueError: <Token ...> was created in a different Context
    # -- which previously crashed event_gen's cleanup *after* the whole
    # response had already streamed successfully, so Starlette never got
    # to send the final chunk and the client saw "peer closed connection
    # without sending complete message body". event_gen() below binds
    # its own token from within its own task context instead, so set()
    # and reset() always happen in the same place.
    set_hunt_context(hunt_id, req.hunter_name)
    logger.info("hunt started", extra={"hypothesis_id": req.hypothesis_id, "siem_type": req.siem_type})

    # Acquired here (not inside event_gen) so that a full queue/timeout
    # raises a normal HTTPException -> proper 503 response, rather than an
    # exception surfacing mid-stream after headers are already sent.
    slot = _HuntSlot()
    await slot.__aenter__()
    await audit.log_hunt_start(hunt_id, req.hunter_name, req.hypothesis_id, req.hypothesis_text)

    events: asyncio.Queue[str | None] = asyncio.Queue()

    async def publish(payload: dict) -> None:
        await events.put(json.dumps(payload, default=str) + "\n")

    async def produce_hunt() -> None:
        """Run independently of the HTTP consumer so a browser disconnect cannot cancel the hunt."""
        gen_ctx_tokens = set_hunt_context(hunt_id, req.hunter_name)
        workload_token = set_model_workload(req.workload_class)
        final_state = dict(state)
        last_step_at = time.perf_counter()
        terminal_recorded = False
        try:
            await publish({"event": "hunt_started", "hunt_id": hunt_id})
            await audit.log_hunt_stage_started(hunt_id, "refresh_hearth_kb")
            await publish({
                "event": "node_started", "node": "refresh_hearth_kb",
                **_agent_stage("refresh_hearth_kb"),
            })
            try:
                async for step in compiled_graph.astream(state, stream_mode="updates"):
                    for node_name, partial in step.items():
                        duration_ms = int((time.perf_counter() - last_step_at) * 1000)
                        last_step_at = time.perf_counter()
                        partial = {} if partial is None else partial
                        final_state.update(partial)
                        stage = _agent_stage(node_name)
                        await audit.log_hunt_step(
                            hunt_id, node_name, partial, duration_ms,
                            stage["agent_name"], stage["model_tier"], stage["model_name"],
                        )
                        await publish({
                            "event": "node_complete", "node": node_name,
                            "duration_ms": duration_ms,
                            "completed_at": datetime.now().astimezone().isoformat(),
                            "data": partial,
                            **stage,
                        })
                        next_node = _next_pipeline_node(node_name, final_state)
                        if next_node:
                            await audit.log_hunt_stage_started(hunt_id, next_node)
                            await publish({
                                "event": "node_started", "node": next_node,
                                **_agent_stage(next_node),
                            })
            except Exception as exc:
                import traceback
                trace = traceback.format_exc()
                logger.error("graph error", exc_info=True, extra={"node": "graph"})
                await audit.log_tool_error(hunt_id, "graph", trace)
                await audit.log_hunt_complete(
                    hunt_id, "failed", "graph", str(exc), _audit_outcome(final_state),
                )
                terminal_recorded = True
                await publish({"event": "error", "error": str(exc)})
                await publish({"event": "hunt_complete", "hunt_id": hunt_id, "state": final_state})
                return

            if final_state.get("reasoning_failed") or final_state.get("verification_failed"):
                stage = "reasoning" if final_state.get("reasoning_failed") else "verifier"
                failure = final_state.get("error") or f"{stage} failed"
                await audit.log_tool_error(
                    hunt_id, stage, failure,
                    {"attempts": final_state.get("reasoning_attempts", 3)},
                )
                await audit.log_hunt_complete(
                    hunt_id, "failed", stage, failure, _audit_outcome(final_state),
                )
                terminal_recorded = True
                await publish({"event": "error", "error": failure})
                await publish({"event": "hunt_complete", "hunt_id": hunt_id, "state": final_state})
                return

            await _create_review_artifacts(hunt_id, final_state, req.hunter_name)
            if final_state.get("report_path"):
                await audit.log_report(
                    hunt_id, final_state["report_path"], final_state.get("reasoning_summary", ""),
                )
            await audit.log_hunt_complete(
                hunt_id, "completed", outcome=_audit_outcome(final_state),
            )
            if final_state.get("report_path"):
                _schedule_risk_refresh(f"hunt_report_generated:{hunt_id}")
            terminal_recorded = True
            logger.info("hunt completed")
            await publish({"event": "hunt_complete", "hunt_id": hunt_id, "state": final_state})
        finally:
            if not terminal_recorded:
                interruption = "Hunt worker stopped before a terminal event."
                await asyncio.shield(audit.log_tool_error(hunt_id, "worker", interruption))
                await asyncio.shield(audit.log_hunt_complete(
                    hunt_id, "failed", "worker", interruption, _audit_outcome(final_state),
                ))
            await slot.__aexit__(None, None, None)
            reset_model_workload(workload_token)
            reset_hunt_context(gen_ctx_tokens)
            await events.put(None)

    producer = asyncio.create_task(produce_hunt(), name=f"hunt-{hunt_id}")
    _background_hunts.add(producer)
    producer.add_done_callback(_background_hunt_done)

    async def event_gen():
        while True:
            event = await events.get()
            if event is None:
                return
            yield event

    return StreamingResponse(event_gen(), media_type="application/x-ndjson")
