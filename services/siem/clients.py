"""
Shared, lazily-initialized clients used by every MCP tool module.
Centralizing these means Phase 2+ tools (new SIEM connectors, new
enrichment tools, etc.) just import from here instead of re-wiring
connections.
"""
import os
import functools
import threading
import httpx
from services.reasoning.model_router import target_for
import redis
import chromadb
from chromadb.config import Settings
from psycopg_pool import ConnectionPool

from services.observability.retry import async_retry

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
CHROMA_HOST = os.environ.get("CHROMA_HOST", "chromadb")
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
POSTGRES_POOL_MIN_SIZE = int(os.environ.get("POSTGRES_POOL_MIN_SIZE", "1"))
POSTGRES_POOL_MAX_SIZE = int(os.environ.get("POSTGRES_POOL_MAX_SIZE", "10"))


@functools.lru_cache(maxsize=1)
def get_chroma_client():
    return chromadb.HttpClient(
        host=CHROMA_HOST,
        port=CHROMA_PORT,
        settings=Settings(anonymized_telemetry=False),
    )


def get_or_create_collection(name: str):
    client = get_chroma_client()
    return client.get_or_create_collection(name=name)


@functools.lru_cache(maxsize=1)
def get_redis_client():
    # redis.Redis checks a connection out of an internal pool per command,
    # so one shared client object is safe for concurrent callers — unlike
    # the raw psycopg connection below, this isn't the "single connection
    # under concurrency" trap.
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


# get_pg_conn() used to hand back a single functools.lru_cache'd psycopg
# connection — the exact same "one connection shared across every caller"
# bug that was fixed in services/observability/audit.py (see that module's
# comment for the full explanation). It's currently unused by any tool, but
# left as-is it's a landmine: the moment a future SOC tool imports it for a
# Postgres lookup, that tool inherits the crash/serialize-under-concurrency
# behavior right back, silently. A raw psycopg connection is not safe to
# share across threads/tasks; a pool hands each caller its own connection
# for the life of one query. Mirrors audit.py's pool pattern so any new
# tool that needs direct Postgres access here is safe by construction
# instead of by remembering to wrap it correctly.
_pg_pool: ConnectionPool | None = None
_pg_pool_lock = threading.Lock()


def get_pg_pool() -> ConnectionPool:
    global _pg_pool
    if _pg_pool is None:
        with _pg_pool_lock:
            if _pg_pool is None:
                _pg_pool = ConnectionPool(
                    POSTGRES_DSN,
                    min_size=POSTGRES_POOL_MIN_SIZE,
                    max_size=POSTGRES_POOL_MAX_SIZE,
                    kwargs={"autocommit": True},
                    open=True,
                )
    return _pg_pool


async def ollama_generate(prompt: str, model: str = None, system: str = None,
                          agent: str = "query_gen") -> str:
    """Call the local Ollama server for generation (used by query_generator, reasoning helpers)."""
    target = target_for(agent)
    model = model or target.model
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "num_ctx": target.num_ctx,
            "num_predict": min(target.num_predict, 512),
        },
    }
    if system:
        payload["system"] = system

    async def _do_request():
        timeout = float(os.environ.get("THOS_FAST_GENERATION_TIMEOUT_SECONDS", "60")) if target.tier == "fast" else float(os.environ.get("OLLAMA_GENERATION_TIMEOUT_SECONDS", "180"))
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{target.host}/api/generate", json=payload)
            resp.raise_for_status()
            body = resp.json()
            return str(body.get("response") or (body.get("message") or {}).get("content") or "").strip()

    retries = int(os.environ.get("OLLAMA_GENERATION_RETRIES", "3"))
    return await async_retry(_do_request, retries=retries, what="clients.ollama_generate")
