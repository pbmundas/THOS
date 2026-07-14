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


async def log_hunt_step(hunt_id: str, node_name: str, output: dict, duration_ms: int | None = None):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO hunt_steps (hunt_id, node_name, output, status, duration_ms)
           VALUES (%s, %s, %s, 'ok', %s)""",
        (hunt_id, node_name, json.dumps(output, default=str), duration_ms),
    )


async def log_tool_error(hunt_id: str, tool_name: str, error_msg: str, payload: dict | None = None):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO tool_errors (tool_name, hunt_id, error_msg, payload)
           VALUES (%s, %s, %s, %s)""",
        (tool_name, hunt_id, error_msg, json.dumps(payload or {}, default=str)),
    )


async def log_hunt_complete(hunt_id: str, status: str):
    await asyncio.to_thread(
        _execute,
        """UPDATE hunts SET status = %s, updated_at = now() WHERE hunt_id = %s""",
        (status, hunt_id),
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


async def create_approval(hunt_id: str, reason: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        INSERT INTO hunt_approvals (hunt_id, reason) VALUES (%s, %s)
        RETURNING approval_id, hunt_id, status, reason, created_at
    """, (hunt_id, reason))
    return rows[0] if rows else None


async def decide_approval(approval_id: str, status: str, decided_by: str) -> dict | None:
    rows = await asyncio.to_thread(_fetch, """
        UPDATE hunt_approvals SET status = %s, decided_by = %s, decided_at = now()
        WHERE approval_id = %s AND status = 'pending'
        RETURNING approval_id, hunt_id, status, reason, decided_by, decided_at
    """, (status, decided_by, approval_id))
    return rows[0] if rows else None


async def list_approvals(status: str | None = "pending", limit: int = 100) -> list[dict]:
    if status:
        query, params = "SELECT * FROM hunt_approvals WHERE status = %s ORDER BY created_at DESC LIMIT %s", (status, limit)
    else:
        query, params = "SELECT * FROM hunt_approvals ORDER BY created_at DESC LIMIT %s", (limit,)
    return await asyncio.to_thread(_fetch, query, params)


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
        """CREATE TABLE IF NOT EXISTS hunt_approvals (approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'pending', reason TEXT, decided_by TEXT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS finding_feedback (feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE CASCADE, finding_ref TEXT, rating TEXT NOT NULL, correction TEXT, analyst_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS cases (case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), hunt_id UUID REFERENCES hunts(hunt_id) ON DELETE SET NULL, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', priority TEXT NOT NULL DEFAULT 'medium', assigned_to TEXT, summary TEXT, sla_due_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
        """CREATE TABLE IF NOT EXISTS case_events (event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), case_id UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE, actor TEXT, event_type TEXT NOT NULL, note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    )
    for statement in statements:
        await asyncio.to_thread(_execute, statement, ())


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


async def export_learning_feedback(limit: int = 5000) -> list[dict]:
    return await asyncio.to_thread(_fetch, """
        SELECT f.hunt_id, f.finding_ref, f.rating, f.correction, f.created_at,
               h.hypothesis_text, h.hypothesis_id
        FROM finding_feedback f JOIN hunts h ON h.hunt_id = f.hunt_id
        ORDER BY f.created_at DESC LIMIT %s
    """, (limit,))
