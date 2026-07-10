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


async def log_hunt_start(hunt_id: str, hunter_name: str, hypothesis_id: str | None,
                          hypothesis_text: str | None):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO hunts (hunt_id, hunter_name, hypothesis_id, hypothesis_text, status)
           VALUES (%s, %s, %s, %s, 'running')
           ON CONFLICT (hunt_id) DO NOTHING""",
        (hunt_id, hunter_name, hypothesis_id, hypothesis_text),
    )


async def log_hunt_step(hunt_id: str, node_name: str, output: dict):
    await asyncio.to_thread(
        _execute,
        """INSERT INTO hunt_steps (hunt_id, node_name, output, status)
           VALUES (%s, %s, %s, 'ok')""",
        (hunt_id, node_name, json.dumps(output, default=str)),
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
