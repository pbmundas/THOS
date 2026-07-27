"""
Audit / technical-tracking layer.

Every hunt, every node execution, and every error gets written to
Postgres (see config/init_db.sql for schema). This is what makes the
platform auditable for a SOC — "what did the AI do, in what order, and
why" — and gives you a place to build dashboards/alerting on top of in
later phases.

Deliberately fails soft: a broken audit write should never take down a
live hunt. Errors are printed to stdout (captured by `docker compose
logs orchestrator`) instead of raised.
"""
import os
import json
import asyncio
import datetime
import logging
import threading

from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
POOL_MIN_SIZE = int(os.environ.get("POSTGRES_POOL_MIN_SIZE", "1"))
POOL_MAX_SIZE = int(os.environ.get("POSTGRES_POOL_MAX_SIZE", "10"))

# A single lru_cache(maxsize=1) psycopg connection used to be shared across
# every concurrent hunt via asyncio.to_thread — sync psycopg connections
# aren't safe for simultaneous use from multiple threads, so concurrent
# hunts would serialize on it at best and error at worst. A real pool hands
# each writer its own connection for the duration of one query.
#
# Guarded by a plain threading.Lock (not asyncio.Lock): _execute runs
# inside asyncio.to_thread's worker threads, not the event loop, so the
# lazy-init race is a genuine multi-thread race, not just a multi-task one.
_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    POSTGRES_DSN,
                    min_size=POOL_MIN_SIZE,
                    max_size=POOL_MAX_SIZE,
                    kwargs={"autocommit": True},
                    open=True,
                )
    return _pool


def close_pool():
    """Call during app shutdown to cleanly release pooled connections."""
    global _pool
    with _pool_lock:
        pool, _pool = _pool, None
    if pool is not None:
        pool.close()


def _execute(query: str, params: tuple):
    try:
        pool = _get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
    except Exception:  # noqa: BLE001 - audit logging must never crash a hunt
        logger.error("audit write failed", exc_info=True)


def _fetch(query: str, params: tuple) -> list[dict]:
    """Run a read/write query that returns rows for the case-management API."""
    try:
        pool = _get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                if not cur.description:
                    return []
                columns = [column.name for column in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    except Exception:  # noqa: BLE001
        logger.error("case-management database operation failed", exc_info=True)
        return []


async def log_hunt_start(hunt_id: str, hunter_name: str, hypothesis_id: str | None,
                          hypothesis_text: str | None):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO hunts (hunt_id, hunter_name, hypothesis_id, hypothesis_text, status)
           VALUES (%s, %s, %s, %s, 'running')
           ON CONFLICT (hunt_id) DO NOTHING""",
        (hunt_id, hunter_name, hypothesis_id, hypothesis_text),
    )


async def log_hunt_step(
    hunt_id: str,
    node_name: str,
    output: dict,
    duration_ms: int | None = None,
    agent_name: str | None = None,
    model_tier: str | None = None,
    model_name: str | None = None,
):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO hunt_steps (
               hunt_id, node_name, output, status, duration_ms,
               agent_name, model_tier, model_name
           ) VALUES (%s, %s, %s, 'ok', %s, %s, %s, %s)""",
        (
            hunt_id, node_name, json.dumps(output, default=str), duration_ms,
            agent_name, model_tier, model_name,
        ),
    )
    await asyncio.to_thread(
        _execute,
        "UPDATE hunts SET last_stage = %s, updated_at = now() WHERE hunt_id = %s",
        (node_name, hunt_id),
    )


async def log_hunt_stage_started(hunt_id: str, node_name: str):
    await asyncio.to_thread(
        _execute,
        "UPDATE hunts SET current_stage = %s, updated_at = now() WHERE hunt_id = %s",
        (node_name, hunt_id),
    )


async def log_tool_error(hunt_id: str, tool_name: str, error_msg: str, payload: dict | None = None):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO tool_errors (tool_name, hunt_id, error_msg, payload)
           VALUES (%s, %s, %s, %s)""",
        (tool_name, hunt_id, error_msg, json.dumps(payload or {}, default=str)),
    )


async def log_hunt_complete(hunt_id: str, status: str, failure_stage: str | None = None,
                            failure_reason: str | None = None, outcome: dict | None = None):
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts SET status = %s, failure_stage = %s, failure_reason = %s,
                  outcome = %s, current_stage = NULL, updated_at = now() WHERE hunt_id = %s""",
        (status, failure_stage, failure_reason, json.dumps(outcome or {}, default=str), hunt_id),
    )


async def log_report(hunt_id: str, file_path: str, summary: str):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO reports (hunt_id, file_path, summary) VALUES (%s, %s, %s)""",
        (hunt_id, file_path, summary),
    )


async def create_case(hunt_id: str | None, title: str, priority: str, assigned_to: str | None,
                      summary: str | None, actor: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        INSERT INTO cases (hunt_id, title, priority, assigned_to, summary)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING case_id, hunt_id, title, status, priority, assigned_to, summary, created_at, updated_at
    """, (hunt_id or None, title, priority, assigned_to or None, summary or None))
    if rows:
        await asyncio.to_thread(_execute,
            "INSERT INTO case_events (case_id, actor, event_type, note) VALUES (%s, %s, 'created', %s)",
            (rows[0]["case_id"], actor, "Case created"))
    return rows[0] if rows else None


async def list_cases(status: str | None = None, limit: int = 100) -> list[dict]:
    if status:
        query, params = "SELECT * FROM cases WHERE status = %s ORDER BY updated_at DESC LIMIT %s", (status, limit)
    else:
        query, params = "SELECT * FROM cases ORDER BY updated_at DESC LIMIT %s", (limit,)
    return await asyncio.to_thread(_fetch, query, params)


async def update_case(case_id: str, status: str | None, priority: str | None, assigned_to: str | None,
                      summary: str | None, actor: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        UPDATE cases SET status = COALESCE(%s, status), priority = COALESCE(%s, priority),
          assigned_to = COALESCE(%s, assigned_to), summary = COALESCE(%s, summary), updated_at = now()
        WHERE case_id = %s
        RETURNING case_id, hunt_id, title, status, priority, assigned_to, summary, created_at, updated_at
    """, (status, priority, assigned_to, summary, case_id))
    if rows:
        await asyncio.to_thread(_execute,
            "INSERT INTO case_events (case_id, actor, event_type, note) VALUES (%s, %s, 'updated', %s)",
            (case_id, actor, "Case fields updated"))
    return rows[0] if rows else None


async def record_feedback(hunt_id: str, finding_ref: str | None, rating: str,
                          correction: str | None, analyst_name: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        INSERT INTO finding_feedback (hunt_id, finding_ref, rating, correction, analyst_name)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING feedback_id, hunt_id, finding_ref, rating, correction, analyst_name, created_at
    """, (hunt_id, finding_ref, rating, correction, analyst_name))
    return rows[0] if rows else None


async def ensure_agentic_schema() -> None:
    """Backfill Phase-2 tables for existing Postgres volumes at startup."""
    statements = (
        """ALTER TABLE hunts ADD COLUMN IF NOT EXISTS last_stage TEXT""",
        """ALTER TABLE hunts ADD COLUMN IF NOT EXISTS current_stage TEXT""",
        """ALTER TABLE hunts ADD COLUMN IF NOT EXISTS failure_stage TEXT""",
        """ALTER TABLE hunts ADD COLUMN IF NOT EXISTS failure_reason TEXT""",
        """ALTER TABLE hunts ADD COLUMN IF NOT EXISTS outcome JSONB NOT NULL DEFAULT '{}'::jsonb""",
        """ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS agent_name TEXT""",
        """ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS model_tier TEXT""",
        """ALTER TABLE hunt_steps ADD COLUMN IF NOT EXISTS model_name TEXT""",
        """CREATE TABLE IF NOT EXISTS hunt_approvals (approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'pending', reason TEXT, approval_type TEXT NOT NULL DEFAULT 'hunt_review', artifact_hash TEXT, decided_by TEXT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """ALTER TABLE hunt_approvals ADD COLUMN IF NOT EXISTS approval_type TEXT NOT NULL DEFAULT 'hunt_review'""",
        """ALTER TABLE hunt_approvals ADD COLUMN IF NOT EXISTS artifact_hash TEXT""",
        """CREATE TABLE IF NOT EXISTS finding_feedback (feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE, finding_ref TEXT, rating TEXT NOT NULL, correction TEXT, analyst_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS cases (case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE SET NULL, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', priority TEXT NOT NULL DEFAULT 'medium', assigned_to TEXT, summary TEXT, sla_due_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS case_events (event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE, actor TEXT, event_type TEXT NOT NULL, note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS forensic_cases (case_id UUID PRIMARY KEY, case_title TEXT NOT NULL, examiner TEXT NOT NULL, evidence_path TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', current_stage TEXT, report_path TEXT, summary TEXT, error_msg TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS forensic_steps (step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), case_id UUID NOT NULL REFERENCES forensic_cases(case_id) ON DELETE CASCADE, stage TEXT NOT NULL, agent_name TEXT NOT NULL, activity TEXT, status TEXT NOT NULL DEFAULT 'ok', duration_ms INTEGER, model_tier TEXT, model_name TEXT, output JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS scheduled_sigma_detections (run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), schedule_id TEXT NOT NULL, rule_id TEXT NOT NULL, rule_title TEXT, rule_source TEXT, level TEXT, siem_type TEXT NOT NULL, status TEXT NOT NULL, events_matched INTEGER NOT NULL DEFAULT 0, matched_events JSONB NOT NULL DEFAULT '[]'::jsonb, analysis JSONB NOT NULL DEFAULT '{}'::jsonb, compiled_query TEXT, query_backend TEXT, error_msg TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS platform_audit_logs (log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), level TEXT NOT NULL DEFAULT 'INFO', service TEXT NOT NULL, category TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, resource TEXT, status_code INTEGER, duration_ms INTEGER, message TEXT NOT NULL, context JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE INDEX IF NOT EXISTS idx_platform_audit_logs_created_at ON platform_audit_logs (created_at DESC)""",
        "ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS compiled_query TEXT",
        "ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS query_backend TEXT",
        "ALTER TABLE scheduled_sigma_detections ADD COLUMN IF NOT EXISTS case_id UUID REFERENCES cases(case_id) ON DELETE SET NULL",
    )
    for statement in statements:
        await asyncio.to_thread(_execute, statement, ())


async def create_forensic_case(
    case_id: str, case_title: str, examiner: str, evidence_path: str,
) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        INSERT INTO forensic_cases (case_id, case_title, examiner, evidence_path, status)
        VALUES (%s, %s, %s, %s, 'queued')
        ON CONFLICT (case_id) DO NOTHING
        RETURNING *
    """, (case_id, case_title, examiner, evidence_path))
    return rows[0] if rows else None


async def forensic_stage_started(case_id: str, stage: str) -> None:
    await asyncio.to_thread(_execute, """
        UPDATE forensic_cases
        SET status = 'running', current_stage = %s, updated_at = now()
        WHERE case_id = %s
    """, (stage, case_id))


async def log_forensic_step(case_id: str, event: dict) -> None:
    await asyncio.to_thread(_execute, """
        INSERT INTO forensic_steps (
            case_id, stage, agent_name, activity, status, duration_ms,
            model_tier, model_name, output
        ) VALUES (%s, %s, %s, %s, 'ok', %s, %s, %s, %s)
    """, (
        case_id, event.get("stage"), event.get("agent_name"), event.get("activity"),
        event.get("duration_ms"), event.get("model_tier"), event.get("model_name"),
        json.dumps(event.get("output") or {}, default=str),
    ))


async def complete_forensic_case(
    case_id: str,
    status: str,
    *,
    report_path: str | None = None,
    summary: str | None = None,
    error_msg: str | None = None,
) -> None:
    await asyncio.to_thread(_execute, """
        UPDATE forensic_cases
        SET status = %s, current_stage = NULL, report_path = %s,
            summary = %s, error_msg = %s, updated_at = now()
        WHERE case_id = %s
    """, (status, report_path, summary, error_msg, case_id))


async def list_forensic_cases(limit: int = 100) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT case_id, case_title, examiner, evidence_path, status, current_stage,
               report_path, summary, error_msg, created_at, updated_at
        FROM forensic_cases ORDER BY created_at DESC LIMIT %s
    """, (max(1, min(limit, 500)),))


async def get_forensic_case(case_id: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        SELECT case_id, case_title, examiner, evidence_path, status, current_stage,
               report_path, summary, error_msg, created_at, updated_at
        FROM forensic_cases WHERE case_id = %s
    """, (case_id,))
    if not rows:
        return None
    steps = await asyncio.to_thread(_fetch, """
        SELECT step_id, stage, agent_name, activity, status, duration_ms,
               model_tier, model_name, output, created_at
        FROM forensic_steps WHERE case_id = %s ORDER BY created_at, step_id
    """, (case_id,))
    return {**rows[0], "steps": steps}


async def reconcile_incomplete_hunts() -> None:
    """Close rows left running by a previous process or disconnected stream."""
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts h SET last_stage = latest.node_name
           FROM (
               SELECT DISTINCT ON (hunt_id) hunt_id, node_name
               FROM hunt_steps ORDER BY hunt_id, created_at DESC
           ) latest
           WHERE h.hunt_id = latest.hunt_id AND h.last_stage IS NULL""",
        (),
    )
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts h
           SET outcome = h.outcome || jsonb_build_object(
               'report_status', 'generated',
               'reasoning_mode', 'legacy_deterministic_fallback',
               'reasoning_degraded', true,
               'reasoning_error', 'Legacy run: reasoning model returned no final response; detailed strike reasons were not persisted by that version.'
           )
           FROM reports r
           WHERE r.hunt_id = h.hunt_id
             AND position('Degraded analysis:' in r.summary) = 1
             AND NOT (h.outcome ? 'reasoning_degraded')""",
        (),
    )
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts
           SET status = 'failed',
               failure_stage = COALESCE(last_stage, 'orchestrator'),
               failure_reason = COALESCE(
                   failure_reason,
                   'Hunt did not reach a terminal event because the orchestrator stopped or the client stream disconnected.'
               ),
               updated_at = now()
           WHERE status IN ('started', 'running')""",
        (),
    )
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts
           SET failure_stage = COALESCE(failure_stage, last_stage, 'unknown'),
               failure_reason = COALESCE(
                   failure_reason,
                   'Legacy hunt failed before this version began persisting a detailed failure reason.'
               ),
               updated_at = now()
           WHERE status = 'failed'
             AND (failure_reason IS NULL OR btrim(failure_reason) = '')""",
        (),
    )


async def list_hunts(limit: int = 100) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT h.hunt_id, h.hunter_name, h.hypothesis_id, h.hypothesis_text,
               h.status, h.last_stage, h.failure_stage, h.failure_reason, h.outcome,
               h.created_at, h.updated_at, r.file_path AS report_path, r.summary
        FROM hunts h
        LEFT JOIN LATERAL (
            SELECT file_path, summary FROM reports
            WHERE hunt_id = h.hunt_id ORDER BY created_at DESC LIMIT 1
        ) r ON true
        ORDER BY h.created_at DESC LIMIT %s
    """, (max(1, min(limit, 500)),))


async def clear_hunt_history() -> dict:
    """Remove hunt-run audit rows while leaving generated report files intact."""
    rows = await asyncio.to_thread(
        _fetch,
        "DELETE FROM hunts RETURNING hunt_id",
        (),
    )
    return {"cleared": len(rows), "hunt_ids": [str(row["hunt_id"]) for row in rows]}


async def hunt_progress(hunt_id: str | None = None, active_only: bool = False) -> dict | None:
    where, params = "", ()
    if hunt_id:
        where, params = "WHERE hunt_id = %s", (hunt_id,)
    elif active_only:
        where = "WHERE status = 'running'"
    rows = await asyncio.to_thread(_fetch, f"""
        SELECT hunt_id, hunter_name, hypothesis_id, hypothesis_text, status,
               last_stage, current_stage, failure_stage, failure_reason, outcome,
               created_at, updated_at
        FROM hunts {where} ORDER BY created_at DESC LIMIT 1
    """, params)
    if not rows:
        return None
    hunt = rows[0]
    steps = await asyncio.to_thread(_fetch, """
        SELECT step_id, node_name, agent_name, model_tier, model_name,
               output, duration_ms, status, error_msg, created_at
        FROM hunt_steps WHERE hunt_id = %s ORDER BY created_at, step_id
    """, (hunt["hunt_id"],))
    return {**hunt, "steps": steps}


async def log_sigma_detection(result: dict) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        INSERT INTO scheduled_sigma_detections (
            schedule_id, rule_id, rule_title, rule_source, level, siem_type,
            status, events_matched, matched_events, analysis, compiled_query,
            query_backend, error_msg, case_id
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (
        result.get("schedule_id"), result.get("rule_id"), result.get("rule_title"),
        result.get("rule_source"), result.get("level"), result.get("siem_type"),
        result.get("status"), int(result.get("events_matched", 0)),
        json.dumps(result.get("matched_events", []), default=str),
        json.dumps(result.get("analysis", {}), default=str), result.get("compiled_query"),
        result.get("query_backend"), result.get("error"), result.get("case_id"),
    ))
    return rows[0] if rows else None


async def list_sigma_detections(limit: int = 100) -> list[dict]:
    rows = await asyncio.to_thread(_fetch, """
        SELECT * FROM scheduled_sigma_detections
        WHERE status = 'detected' AND events_matched > 0
        ORDER BY created_at DESC LIMIT %s
    """, (max(1, min(limit, 500)),))
    return [_with_detection_uid(row) for row in rows]


def _with_detection_uid(row: dict) -> dict:
    result = dict(row)
    result["detection_uid"] = f"DET-{str(result.get('run_id') or 'UNKNOWN').upper()}"
    return result


async def get_sigma_detection(run_id: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        SELECT * FROM scheduled_sigma_detections WHERE run_id = %s LIMIT 1
    """, (run_id,))
    return _with_detection_uid(rows[0]) if rows else None


async def save_sigma_ai_analysis(run_id: str, analysis: dict) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        UPDATE scheduled_sigma_detections
        SET analysis = COALESCE(analysis, '{}'::jsonb)
            || jsonb_build_object('ai_analysis', %s::jsonb)
        WHERE run_id = %s
        RETURNING *
    """, (json.dumps(analysis, default=str), run_id))
    return _with_detection_uid(rows[0]) if rows else None


async def risk_source_hunts(limit: int = 5000) -> list[dict]:
    """Return completed report-bearing hunts for bounded risk correlation."""
    return await asyncio.to_thread(_fetch, """
        SELECT h.hunt_id, h.hypothesis_id, h.hypothesis_text, h.status,
               h.outcome, h.created_at, h.updated_at,
               r.file_path AS report_path, r.summary
        FROM hunts h
        JOIN LATERAL (
            SELECT file_path, summary FROM reports
            WHERE hunt_id = h.hunt_id ORDER BY created_at DESC LIMIT 1
        ) r ON true
        WHERE h.status = 'completed'
        ORDER BY h.created_at DESC LIMIT %s
    """, (max(1, min(int(limit), 10_000)),))


async def risk_source_detections(limit: int = 5000) -> list[dict]:
    """Return positive scheduled detections for bounded risk correlation."""
    return await asyncio.to_thread(_fetch, """
        SELECT * FROM scheduled_sigma_detections
        WHERE events_matched > 0
        ORDER BY created_at DESC LIMIT %s
    """, (max(1, min(int(limit), 10_000)),))


async def hunt_metrics(hunt_id: str) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT node_name, COUNT(*) AS executions, COALESCE(AVG(duration_ms), 0)::INTEGER AS avg_duration_ms,
               COALESCE(MAX(duration_ms), 0) AS max_duration_ms
        FROM hunt_steps WHERE hunt_id = %s GROUP BY node_name ORDER BY max_duration_ms DESC
    """, (hunt_id,))


async def recent_hunt_memory(technique_id: str, limit: int = 3) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT h.hunt_id, h.created_at, h.status, r.summary
        FROM hunts h LEFT JOIN reports r ON r.hunt_id = h.hunt_id
        WHERE h.hypothesis_text ILIKE %s AND h.status = 'completed'
        ORDER BY h.created_at DESC LIMIT %s
    """, (f"%{technique_id}%", limit))


async def hypothesis_last_runs() -> list[dict]:
    """Return the newest audit row for each catalogue hypothesis."""
    return await asyncio.to_thread(_fetch, """
        SELECT DISTINCT ON (hypothesis_id)
               hypothesis_id, hunt_id, status, created_at AS last_ran_at
        FROM hunts
        WHERE hypothesis_id IS NOT NULL AND hypothesis_id <> ''
        ORDER BY hypothesis_id, created_at DESC
    """, ())


async def hypothesis_duration_statistics(limit_per_hypothesis: int = 30) -> list[dict]:
    """Return rolling p50/p95 wall-clock duration for each hypothesis."""
    return await asyncio.to_thread(_fetch, """
        WITH ranked AS (
            SELECT hypothesis_id, status,
                   GREATEST(
                       0,
                       EXTRACT(EPOCH FROM (updated_at - created_at)) * 1000
                   )::BIGINT AS duration_ms,
                   ROW_NUMBER() OVER (
                       PARTITION BY hypothesis_id ORDER BY created_at DESC
                   ) AS recency
            FROM hunts
            WHERE hypothesis_id IS NOT NULL
              AND hypothesis_id <> ''
              AND status IN ('completed', 'failed')
        )
        SELECT hypothesis_id,
               COUNT(*)::INTEGER AS sample_count,
               PERCENTILE_CONT(0.5) WITHIN GROUP (
                   ORDER BY duration_ms
               )::BIGINT AS p50_duration_ms,
               PERCENTILE_CONT(0.95) WITHIN GROUP (
                   ORDER BY duration_ms
               )::BIGINT AS p95_duration_ms,
               MAX(duration_ms)::BIGINT AS max_duration_ms
        FROM ranked
        WHERE recency <= %s
        GROUP BY hypothesis_id
        ORDER BY hypothesis_id
    """, (max(1, min(int(limit_per_hypothesis), 100)),))


async def log_platform_event(event: dict) -> None:
    await asyncio.to_thread(
        _execute,
        """
        INSERT INTO platform_audit_logs (
            level, service, category, actor, action, resource, status_code,
            duration_ms, message, context
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            str(event.get("level") or "INFO").upper()[:16],
            str(event.get("service") or "thos")[:120],
            str(event.get("category") or "operation")[:120],
            str(event.get("actor") or "")[:160] or None,
            str(event.get("action") or "event")[:200],
            str(event.get("resource") or "")[:1000] or None,
            int(event["status_code"]) if event.get("status_code") is not None else None,
            int(event["duration_ms"]) if event.get("duration_ms") is not None else None,
            str(event.get("message") or event.get("action") or "event")[:4000],
            json.dumps(event.get("context") or {}, default=str),
        ),
    )


async def list_platform_audit_logs(
    hours: int = 24,
    limit: int = 500,
    level: str = "all",
    query: str = "",
) -> list[dict]:
    """Combine request, workflow, detection, forensic, and error events."""
    normalized_level = str(level or "all").lower()
    search = str(query or "").strip()[:500]
    return await asyncio.to_thread(_fetch, """
        WITH timeline AS (
            SELECT log_id::TEXT AS id, created_at AS timestamp, level, service,
                   category, COALESCE(actor, '') AS actor, action,
                   COALESCE(resource, '') AS resource, status_code, duration_ms,
                   message, context
            FROM platform_audit_logs
            UNION ALL
            SELECT hs.step_id::TEXT, hs.created_at,
                   CASE WHEN hs.status = 'error' THEN 'ERROR' ELSE 'INFO' END,
                   'thos-orchestrator', 'hunt_workflow',
                   COALESCE(h.hunter_name, ''), hs.node_name,
                   h.hunt_id::TEXT, NULL, hs.duration_ms,
                   CONCAT(
                       COALESCE(h.hypothesis_id, 'dynamic hunt'), ' · ',
                       COALESCE(hs.agent_name, hs.node_name), ' completed'
                   ),
                   jsonb_build_object(
                       'hunt_id', h.hunt_id,
                       'hypothesis_id', h.hypothesis_id,
                       'model_tier', hs.model_tier,
                       'model_name', hs.model_name,
                       'status', hs.status
                   )
            FROM hunt_steps hs JOIN hunts h ON h.hunt_id = hs.hunt_id
            UNION ALL
            SELECT error_id::TEXT, created_at, 'ERROR', 'thos-orchestrator',
                   'tool_error', '', tool_name, COALESCE(hunt_id::TEXT, ''),
                   NULL, NULL, COALESCE(error_msg, 'Tool execution failed'),
                   COALESCE(payload, '{}'::jsonb)
            FROM tool_errors
            UNION ALL
            SELECT step_id::TEXT, created_at,
                   CASE WHEN status = 'ok' THEN 'INFO' ELSE 'ERROR' END,
                   'thos-forensics', 'forensic_workflow', '', stage,
                   case_id::TEXT, NULL, duration_ms,
                   CONCAT(COALESCE(agent_name, 'Forensic agent'), ' · ',
                          COALESCE(activity, stage)),
                   jsonb_build_object('case_id', case_id, 'status', status)
            FROM forensic_steps
            UNION ALL
            SELECT run_id::TEXT, created_at,
                   CASE WHEN status = 'failed' THEN 'ERROR'
                        WHEN events_matched > 0 THEN 'WARNING' ELSE 'INFO' END,
                   'thos-detection', 'sigma_detection', '', status,
                   rule_id, NULL,
                   CASE WHEN analysis ? 'duration_ms'
                        THEN (analysis->>'duration_ms')::INTEGER ELSE NULL END,
                   CONCAT(COALESCE(rule_title, rule_id), ' · ',
                          events_matched, ' matched event(s)'),
                   jsonb_build_object(
                       'rule_id', rule_id, 'siem_type', siem_type,
                       'events_matched', events_matched
                   )
            FROM scheduled_sigma_detections
        )
        SELECT * FROM timeline
        WHERE timestamp >= now() - (%s * INTERVAL '1 hour')
          AND (%s = 'all' OR LOWER(level) = %s)
          AND (
              %s = '' OR CONCAT_WS(
                  ' ', service, category, actor, action, resource, message
              ) ILIKE %s
          )
        ORDER BY timestamp DESC
        LIMIT %s
    """, (
        max(1, min(int(hours), 24 * 365)),
        normalized_level,
        normalized_level,
        search,
        f"%{search}%",
        max(1, min(int(limit), 2000)),
    ))


async def operations_dashboard(hours: int = 24) -> dict:
    """Aggregate the daily SOC operating picture for the Overview page."""
    bounded_hours = max(1, min(int(hours), 24 * 365))
    summary_rows = await asyncio.to_thread(_fetch, """
        SELECT COUNT(*)::INTEGER AS hunts_total,
               COUNT(*) FILTER (WHERE status = 'completed')::INTEGER AS hunts_completed,
               COUNT(*) FILTER (WHERE status = 'failed')::INTEGER AS hunts_failed,
               COUNT(*) FILTER (WHERE status = 'running')::INTEGER AS hunts_running,
               COUNT(DISTINCT hypothesis_id)::INTEGER AS hypotheses_hunted,
               COALESCE(AVG(
                   EXTRACT(EPOCH FROM (updated_at - created_at)) * 1000
               ) FILTER (WHERE status IN ('completed', 'failed')), 0)::BIGINT
                   AS avg_hunt_duration_ms,
               COALESCE(SUM(
                   CASE WHEN (outcome->>'records_analyzed') ~ '^[0-9]+$'
                        THEN (outcome->>'records_analyzed')::INTEGER ELSE 0 END
               ), 0)::BIGINT AS records_analyzed,
               COUNT(*) FILTER (
                   WHERE outcome->>'reasoning_mode' =
                         'deterministic_negative_screening'
               )::INTEGER AS model_reasoning_skipped,
               COUNT(*) FILTER (
                   WHERE COALESCE((outcome->>'reasoning_degraded')::BOOLEAN, false)
               )::INTEGER AS degraded_hunts
        FROM hunts
        WHERE created_at >= now() - (%s * INTERVAL '1 hour')
    """, (bounded_hours,))
    detection_rows = await asyncio.to_thread(_fetch, """
        SELECT COUNT(*)::INTEGER AS detection_runs,
               COUNT(*) FILTER (WHERE events_matched > 0)::INTEGER AS detections_triggered,
               COALESCE(SUM(events_matched), 0)::BIGINT AS matched_events,
               COUNT(DISTINCT rule_id)::INTEGER AS distinct_rules
        FROM scheduled_sigma_detections
        WHERE created_at >= now() - (%s * INTERVAL '1 hour')
    """, (bounded_hours,))
    supporting_rows = await asyncio.to_thread(_fetch, """
        SELECT
          (SELECT COUNT(*) FROM reports
           WHERE created_at >= now() - (%s * INTERVAL '1 hour'))::INTEGER AS reports_created,
          (SELECT COUNT(*) FROM forensic_cases
           WHERE created_at >= now() - (%s * INTERVAL '1 hour'))::INTEGER AS forensic_cases,
          (SELECT COUNT(*) FROM forensic_cases
           WHERE status = 'running')::INTEGER AS forensics_running,
          (SELECT COUNT(*) FROM tool_errors
           WHERE created_at >= now() - (%s * INTERVAL '1 hour'))::INTEGER AS tool_errors
    """, (bounded_hours, bounded_hours, bounded_hours))
    trend = await asyncio.to_thread(_fetch, """
        WITH bounds AS (
          SELECT CASE WHEN %s <= 48 THEN 'hour' ELSE 'day' END AS grain,
                 CASE WHEN %s <= 48 THEN INTERVAL '1 hour' ELSE INTERVAL '1 day' END AS step
        ),
        buckets AS (
          SELECT generate_series(
              date_trunc((SELECT grain FROM bounds),
                         now() - (%s * INTERVAL '1 hour')),
              date_trunc((SELECT grain FROM bounds), now()),
              (SELECT step FROM bounds)
          ) AS bucket
        ),
        hunt_counts AS (
          SELECT date_trunc((SELECT grain FROM bounds), created_at) AS bucket,
                 COUNT(*)::INTEGER AS hunts,
                 COUNT(*) FILTER (WHERE status = 'failed')::INTEGER AS failures
          FROM hunts
          WHERE created_at >= now() - (%s * INTERVAL '1 hour')
          GROUP BY 1
        ),
        detection_counts AS (
          SELECT date_trunc((SELECT grain FROM bounds), created_at) AS bucket,
                 COUNT(*) FILTER (WHERE events_matched > 0)::INTEGER AS detections,
                 COALESCE(SUM(events_matched), 0)::BIGINT AS events
          FROM scheduled_sigma_detections
          WHERE created_at >= now() - (%s * INTERVAL '1 hour')
          GROUP BY 1
        )
        SELECT b.bucket, COALESCE(h.hunts, 0) AS hunts,
               COALESCE(h.failures, 0) AS failures,
               COALESCE(d.detections, 0) AS detections,
               COALESCE(d.events, 0) AS events
        FROM buckets b
        LEFT JOIN hunt_counts h USING (bucket)
        LEFT JOIN detection_counts d USING (bucket)
        ORDER BY b.bucket
    """, (bounded_hours, bounded_hours, bounded_hours, bounded_hours, bounded_hours))
    severities = await asyncio.to_thread(_fetch, """
        SELECT LOWER(COALESCE(level, 'unknown')) AS severity,
               COUNT(*)::INTEGER AS runs,
               COALESCE(SUM(events_matched), 0)::BIGINT AS events
        FROM scheduled_sigma_detections
        WHERE created_at >= now() - (%s * INTERVAL '1 hour')
        GROUP BY 1 ORDER BY events DESC, runs DESC
    """, (bounded_hours,))
    top_hypotheses = await asyncio.to_thread(_fetch, """
        SELECT COALESCE(hypothesis_id, 'dynamic') AS hypothesis_id,
               LEFT(MAX(COALESCE(hypothesis_text, 'Dynamic hypothesis')), 220) AS title,
               COUNT(*)::INTEGER AS runs,
               COUNT(*) FILTER (WHERE status = 'completed')::INTEGER AS completed,
               COUNT(*) FILTER (WHERE status = 'failed')::INTEGER AS failed,
               MAX(created_at) AS last_run_at
        FROM hunts
        WHERE created_at >= now() - (%s * INTERVAL '1 hour')
        GROUP BY hypothesis_id
        ORDER BY runs DESC, last_run_at DESC LIMIT 8
    """, (bounded_hours,))
    agents = await asyncio.to_thread(_fetch, """
        SELECT hs.node_name,
               COALESCE(MAX(hs.agent_name), hs.node_name) AS agent_name,
               COUNT(*)::INTEGER AS executions,
               COALESCE(AVG(hs.duration_ms), 0)::BIGINT AS avg_duration_ms,
               COALESCE(SUM(hs.duration_ms), 0)::BIGINT AS total_duration_ms,
               COUNT(*) FILTER (WHERE hs.status = 'error')::INTEGER AS errors
        FROM hunt_steps hs JOIN hunts h ON h.hunt_id = hs.hunt_id
        WHERE h.created_at >= now() - (%s * INTERVAL '1 hour')
        GROUP BY hs.node_name ORDER BY total_duration_ms DESC LIMIT 10
    """, (bounded_hours,))
    recent = await list_platform_audit_logs(
        hours=bounded_hours, limit=16, level="all", query=""
    )
    summary = {
        **(summary_rows[0] if summary_rows else {}),
        **(detection_rows[0] if detection_rows else {}),
        **(supporting_rows[0] if supporting_rows else {}),
    }
    total = int(summary.get("hunts_total") or 0)
    completed = int(summary.get("hunts_completed") or 0)
    summary["completion_rate"] = round(completed * 100 / total, 1) if total else 0
    return {
        "hours": bounded_hours,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": summary,
        "trend": trend,
        "detection_severity": severities,
        "top_hypotheses": top_hypotheses,
        "agent_performance": agents,
        "recent_activity": recent,
    }


async def export_learning_feedback(limit: int = 5000) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT f.hunt_id, f.finding_ref, f.rating, f.correction, f.created_at,
               h.hypothesis_text, h.hypothesis_id
        FROM finding_feedback f JOIN hunts h ON h.hunt_id = f.hunt_id
        ORDER BY f.created_at DESC LIMIT %s
    """, (limit,))
