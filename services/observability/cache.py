"""
Cache tool — Redis-backed caching for repeated SIEM queries and LLM
calls. Reduces load on the SIEM and Ollama when hunters iterate on the
same hypothesis, and provides a simple rate-limit counter.
"""
import hashlib
import json
import logging
from services.siem.clients import get_redis_client

DEFAULT_TTL_SECONDS = 900  # 15 minutes
logger = logging.getLogger(__name__)


def _key(namespace: str, payload: str) -> str:
    digest = hashlib.sha256(payload.encode()).hexdigest()[:24]
    return f"thos:{namespace}:{digest}"


def cache_get(namespace: str, payload: str):
    try:
        r = get_redis_client()
        val = r.get(_key(namespace, payload))
    except Exception:  # cache availability must never break a hunt
        logger.warning("cache read failed for namespace %s", namespace, exc_info=True)
        return None
    if not val:
        return None
    try:
        value = json.loads(val)
    except (TypeError, json.JSONDecodeError):
        logger.warning("discarding corrupt cache entry in namespace %s", namespace)
        return None
    # Earlier versions cached empty model responses. Treat them as a cache
    # miss so a transient Ollama failure cannot poison all identical hunts
    # for the full TTL.
    return None if isinstance(value, str) and not value.strip() else value


def cache_set(namespace: str, payload: str, value, ttl: int = DEFAULT_TTL_SECONDS):
    if isinstance(value, str) and not value.strip():
        return
    try:
        r = get_redis_client()
        r.set(_key(namespace, payload), json.dumps(value), ex=ttl)
    except Exception:  # a cache outage is a performance issue, not a hunt failure
        logger.warning("cache write failed for namespace %s", namespace, exc_info=True)


def rate_limit_check(bucket: str, limit: int, window_seconds: int = 60) -> bool:
    """Simple fixed-window rate limiter. Returns True if under the limit."""
    r = get_redis_client()
    key = f"thos:ratelimit:{bucket}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, window_seconds)
    return count <= limit
