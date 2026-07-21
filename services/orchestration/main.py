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
resumes a paused graph (e.g. after a human-approval gate) using
LangGraph's checkpointing, instead of always running start-to-finish.
"""
import base64
import json
import logging
import os
import secrets
import uuid
import asyncio
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

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

# As early as possible: attaches one stdout JSON handler to the root
# logger so every logger.*() call in this process (this module, graph
# nodes, mcp_client, audit, retry, ...) emits structured, aggregator-
# ready lines instead of relying on Python's unformatted default
# handler. See services/observability/logging_config.py.
configure_logging("thos-orchestrator")
logger = logging.getLogger(__name__)

app = FastAPI(title="THOS Orchestrator", version="1.0.0")

# --- Auth ---------------------------------------------------------------
# This service can run hunts (which call every SOC tool via MCP) and read
# every generated report. It sits on the network right alongside the chat
# UI, so it needs its own credential check rather than trusting that only
# the chat UI can reach it. Callers must send
# `Authorization: Bearer <ORCHESTRATOR_API_KEY>`. Same weak-default /
# loud-warning pattern as MCP_AUTH_TOKEN below — works out of the box for
# local dev, must be overridden with a real secret before this is
# reachable by anyone else.
_DEFAULT_ORCHESTRATOR_API_KEY = "thos_change_me_orchestrator_key"
ORCHESTRATOR_API_KEY = os.environ.get("ORCHESTRATOR_API_KEY", _DEFAULT_ORCHESTRATOR_API_KEY)
if ORCHESTRATOR_API_KEY == _DEFAULT_ORCHESTRATOR_API_KEY:
    logger.warning(
        "ORCHESTRATOR_API_KEY is unset, using the built-in default. Set a "
        "real secret (and mirror it in the chat-ui's ORCHESTRATOR_API_KEY) "
        "before exposing this service beyond a trusted local dev network."
    )


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
MAX_REASONING_FOLLOWUPS = int(os.environ.get("MAX_REASONING_FOLLOWUPS", "1"))


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


# --- Concurrency gate ------------------------------------------------------
# The rate limiter above only throttles *how often* one hunter can fire
# requests — it does nothing to stop N different hunters from each starting
# a hunt at the same moment and piling up as competing asyncio tasks against
# the single Ollama model, the single Postgres pool, and the single MCP
# server behind this one process. Previously there was no cap at all: every
# accepted request just ran the full graph concurrently, so Ollama (which
# can really only usefully serve requests ~one-at-a-time on typical
# single-GPU/CPU deployments) would thrash between contexts and every
# in-flight hunt would slow down together instead of queuing predictably.
#
# MAX_CONCURRENT_HUNTS caps how many hunts can be *actively running* through
# the graph at once. MAX_QUEUED_HUNTS caps how many additional requests may
# wait for a free slot before we start rejecting outright — a bounded queue,
# not unbounded pile-up. HUNT_QUEUE_TIMEOUT_SECONDS bounds how long a queued
# request will wait before giving up, so a caller gets a clear timeout
# instead of hanging indefinitely behind a backlog.
MAX_CONCURRENT_HUNTS = int(os.environ.get("MAX_CONCURRENT_HUNTS", "2"))
MAX_QUEUED_HUNTS = int(os.environ.get("MAX_QUEUED_HUNTS", "5"))
HUNT_QUEUE_TIMEOUT_SECONDS = float(os.environ.get("HUNT_QUEUE_TIMEOUT_SECONDS", "120"))

_hunt_semaphore = asyncio.Semaphore(MAX_CONCURRENT_HUNTS)
_hunt_queue_depth = 0
_hunt_queue_lock = asyncio.Lock()


class _HuntSlot:
    """Async context manager that enforces the concurrency gate.

    Raises HTTPException(503) immediately if the bounded wait queue is
    already full, or HTTPException(503) after HUNT_QUEUE_TIMEOUT_SECONDS if
    a slot never frees up. Otherwise blocks (as a queued waiter) until a
    hunt slot is available, then holds that slot until released.
    """

    async def __aenter__(self):
        global _hunt_queue_depth
        async with _hunt_queue_lock:
            if _hunt_queue_depth >= MAX_QUEUED_HUNTS:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"THOS is at capacity ({MAX_CONCURRENT_HUNTS} hunts running, "
                        f"{MAX_QUEUED_HUNTS} queued). Please retry shortly."
                    ),
                )
            _hunt_queue_depth += 1
        try:
            try:
                await asyncio.wait_for(
                    _hunt_semaphore.acquire(), timeout=HUNT_QUEUE_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"Timed out after {HUNT_QUEUE_TIMEOUT_SECONDS}s waiting for a "
                        f"free hunt slot ({MAX_CONCURRENT_HUNTS} running concurrently). "
                        f"Please retry shortly."
                    ),
                )
        finally:
            async with _hunt_queue_lock:
                _hunt_queue_depth -= 1
        return self

    async def __aexit__(self, exc_type, exc, tb):
        _hunt_semaphore.release()
        return False


@app.on_event("shutdown")
async def _shutdown():
    # Cleanly tear down the shared MCP client session (see mcp_client.py)
    # and release pooled Postgres connections (see audit.py).
    await mcp_client.close()
    audit.close_pool()


@app.on_event("startup")
async def _ensure_agentic_schema():
    await audit.ensure_agentic_schema()


class HuntRequest(BaseModel):
    hunter_name: str = "anonymous"
    hypothesis_id: str | None = None
    hypothesis_text: str | None = None
    siem_type: str = "mock"
    # Only used when siem_type == "folder": local directory containing
    # log artifacts (evtx/log/syslog/csv/CEF/JSON/ECS/xml/txt/pcap) to
    # hunt against instead of a live SIEM API.
    log_source_path: str | None = None
    max_iterations: int = 3
    # "1" = Executive cover page (plain-language, for management/compliance)
    # "2" = SOC Analyst cover panel (technique/tactic/ingestion-stats table)
    cover_style: str = "1"


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


class ApprovalDecisionRequest(BaseModel):
    status: str
    decided_by: str


class FeedbackRequest(BaseModel):
    hunt_id: str
    rating: str
    finding_ref: str | None = None
    correction: str | None = None
    analyst_name: str = "api-user"


class RulePromotionRequest(BaseModel):
    hunt_id: str
    rule_yaml: str
    approved_by: str


def _initial_state(hunt_id: str, req: HuntRequest) -> HuntState:
    return {
        "hunt_id": hunt_id,
        "hunter_name": req.hunter_name,
        "siem_type": req.siem_type,
        "log_source_path": req.log_source_path,
        "hypothesis_id": req.hypothesis_id,
        "hypothesis_text": req.hypothesis_text or "",
        "logs": [],
        "iteration": 0,
        "max_iterations": req.max_iterations,
        "need_more_logs": False,
        "executed_queries": [],
        "max_reasoning_followups": max(0, MAX_REASONING_FOLLOWUPS),
        "enrichment": {},
        "cover_style": req.cover_style,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/hypotheses", dependencies=[Depends(require_api_key)])
async def hypotheses(tactic: str = ""):
    """Proxy to the HEARTH hypothesis tool so the chat-ui doesn't need direct MCP access."""
    return await call_tool("list_hearth_hypotheses", {"tactic": tactic})


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


@app.post("/approvals/{approval_id}/decision", dependencies=[Depends(require_api_key)])
async def decide_approval(approval_id: str, request: ApprovalDecisionRequest):
    if request.status not in {"approved", "rejected"}:
        raise HTTPException(status_code=422, detail="status must be approved or rejected")
    result = await audit.decide_approval(approval_id, request.status, request.decided_by)
    if result is None:
        raise HTTPException(status_code=404, detail="pending approval not found")
    return result


@app.get("/approvals", dependencies=[Depends(require_api_key)])
async def approvals(status: str | None = "pending", limit: int = 100):
    if status and status not in {"pending", "approved", "rejected"}:
        raise HTTPException(status_code=422, detail="invalid approval status")
    return await audit.list_approvals(status, max(1, min(limit, 200)))


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


@app.post("/detection-rules/promote", dependencies=[Depends(require_api_key)], status_code=201)
async def promote_detection_rule(request: RulePromotionRequest):
    """Promote an approved proposal to staging only; live rules remain untouched."""
    rule = request.rule_yaml.strip()
    if not request.hunt_id.strip() or not request.approved_by.strip():
        raise HTTPException(status_code=422, detail="hunt_id and approved_by are required")
    if len(rule) > 20_000 or "status: experimental" not in rule or "title:" not in rule or "detection:" not in rule:
        raise HTTPException(status_code=422, detail="only an experimental THOS detection proposal may be staged")
    staging = Path(os.environ.get("DETECTION_PROPOSALS_DIR", "/data/detection_rule_proposals"))
    staging.mkdir(parents=True, exist_ok=True)
    safe_hunt = "".join(char for char in request.hunt_id if char.isalnum() or char == "-")[:64]
    path = staging / f"{safe_hunt}_approved.yml"
    path.write_text(f"# Approved by: {request.approved_by}\n# Hunt: {request.hunt_id}\n{rule}\n", encoding="utf-8")
    return {"status": "staged", "path": str(path), "message": "Rule is staged only; review and merge it into the live ruleset through change control."}


async def _create_review_artifacts(hunt_id: str, final_state: dict, owner: str) -> None:
    """Persist approval + case artifacts once the verifier requires review."""
    if not final_state.get("human_approval_required"):
        return
    if final_state.get("approval_id") or final_state.get("case_id"):
        return
    approval = await audit.create_approval(
        hunt_id, final_state.get("escalation_reason") or "Verifier requested analyst review",
    )
    if approval:
        final_state["approval_id"] = str(approval["approval_id"])
    case = await audit.create_case(
        hunt_id, f"Analyst review required: {final_state.get('technique_name') or 'THOS hunt'}",
        "high", owner, final_state.get("reasoning_summary"), "thos-verifier",
    )
    if case:
        final_state["case_id"] = str(case["case_id"])


@app.post("/hunt", dependencies=[Depends(require_api_key)])
async def run_hunt(req: HuntRequest):
    """Run a full hunt (hypothesis -> query -> fetch -> process -> SOC tools
    -> reasoning -> [loop] -> report) and return the final state."""
    await _enforce_hunt_rate_limit(req.hunter_name)
    hunt_id = str(uuid.uuid4())
    state = _initial_state(hunt_id, req)

    # Binds hunt_id/hunter_name onto every log line emitted anywhere in
    # this request's async context from here on -- this module, graph
    # nodes, mcp_client, audit, retry -- without threading hunt_id
    # through every call site by hand. Reset in `finally` so the next
    # request handled by this worker (or logging done outside any hunt)
    # doesn't inherit a stale hunt_id.
    ctx_tokens = set_hunt_context(hunt_id, req.hunter_name)
    try:
        logger.info("hunt started", extra={"hypothesis_id": req.hypothesis_id, "siem_type": req.siem_type})

        async with _HuntSlot():
            await audit.log_hunt_start(hunt_id, req.hunter_name, req.hypothesis_id, req.hypothesis_text)

            final_state = dict(state)
            last_step_at = time.perf_counter()
            try:
                async for step in compiled_graph.astream(state, stream_mode="updates"):
                    for node_name, partial in step.items():
                        duration_ms = int((time.perf_counter() - last_step_at) * 1000)
                        last_step_at = time.perf_counter()
                        if partial is None:
                            logger.warning("node '%s' returned None instead of a dict — skipping merge", node_name, extra={"node": node_name})
                            await audit.log_tool_error(hunt_id, node_name, "node returned None instead of a partial-state dict")
                            continue
                        final_state.update(partial)
                        await audit.log_hunt_step(hunt_id, node_name, partial, duration_ms)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error("graph error", exc_info=True, extra={"node": "graph"})
                await audit.log_tool_error(hunt_id, "graph", tb)
                await audit.log_hunt_complete(hunt_id, "failed")
                return {"hunt_id": hunt_id, "error": str(e), "state": final_state}

            await audit.log_hunt_complete(hunt_id, "completed")
            await _create_review_artifacts(hunt_id, final_state, req.hunter_name)
            if final_state.get("report_path"):
                await audit.log_report(hunt_id, final_state["report_path"], final_state.get("reasoning_summary", ""))

            logger.info("hunt completed")
            return final_state
    finally:
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

    async def event_gen():
        # Own context bind, own token -- see the long comment above for
        # why this can't just reuse the outer ctx_tokens.
        gen_ctx_tokens = set_hunt_context(hunt_id, req.hunter_name)
        final_state = dict(state)
        last_step_at = time.perf_counter()
        try:
            yield json.dumps({"event": "hunt_started", "hunt_id": hunt_id}) + "\n"
            try:
                async for step in compiled_graph.astream(state, stream_mode="updates"):
                    for node_name, partial in step.items():
                        duration_ms = int((time.perf_counter() - last_step_at) * 1000)
                        last_step_at = time.perf_counter()
                        if partial is None:
                            logger.warning("node '%s' returned None instead of a dict — skipping merge", node_name, extra={"node": node_name})
                            await audit.log_tool_error(hunt_id, node_name, "node returned None instead of a partial-state dict")
                            continue
                        final_state.update(partial)
                        await audit.log_hunt_step(hunt_id, node_name, partial, duration_ms)
                        yield json.dumps({"event": "node_complete", "node": node_name, "data": partial}, default=str) + "\n"
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error("graph error", exc_info=True, extra={"node": "graph"})
                await audit.log_tool_error(hunt_id, "graph", tb)
                await audit.log_hunt_complete(hunt_id, "failed")
                yield json.dumps({"event": "error", "error": str(e)}) + "\n"
                return

            try:
                await audit.log_hunt_complete(hunt_id, "completed")
                await _create_review_artifacts(hunt_id, final_state, req.hunter_name)
                if final_state.get("report_path"):
                    await audit.log_report(hunt_id, final_state["report_path"], final_state.get("reasoning_summary", ""))
            except Exception as e:
                # The graph itself already finished successfully at this
                # point — headers and prior chunks are already on the wire,
                # so an unguarded failure here (e.g. a Postgres hiccup)
                # used to kill the connection mid-stream instead of
                # surfacing as a normal error line. Report it as a normal
                # 'error' event instead; the hunt's actual results
                # (including the report file, if one was written) are not
                # lost, only this final bookkeeping step failed.
                logger.error("post-hunt audit/report bookkeeping failed", exc_info=True, extra={"node": "post_hunt"})
                yield json.dumps({
                    "event": "error",
                    "error": f"hunt completed but final bookkeeping failed: {e}",
                }) + "\n"
                yield json.dumps({"event": "hunt_complete", "hunt_id": hunt_id, "state": final_state}, default=str) + "\n"
                return

            logger.info("hunt completed")
            yield json.dumps({"event": "hunt_complete", "hunt_id": hunt_id, "state": final_state}, default=str) + "\n"
        finally:
            # Always release the concurrency slot, whether the stream
            # finished, errored, or the client disconnected early.
            await slot.__aexit__(None, None, None)
            reset_hunt_context(gen_ctx_tokens)

    return StreamingResponse(event_gen(), media_type="application/x-ndjson")
