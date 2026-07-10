"""
Cache tool — Redis-backed caching for repeated SIEM queries and LLM
calls. Reduces load on the SIEM and Ollama when hunters iterate on the
same hypothesis, and provides a simple rate-limit counter.
"""
import hashlib
import json
from services.siem.clients import get_redis_client

DEFAULT_TTL_SECONDS = 900  # 15 minutes


def _key(namespace: str, payload: str) -> str:
    digest = hashlib.sha256(payload.encode()).hexdigest()[:24]
    return f"thos:{namespace}:{digest}"


def cache_get(namespace: str, payload: str):
    r = get_redis_client()
    val = r.get(_key(namespace, payload))
    return json.loads(val) if val else None


def cache_set(namespace: str, payload: str, value, ttl: int = DEFAULT_TTL_SECONDS):
    r = get_redis_client()
    r.set(_key(namespace, payload), json.dumps(value), ex=ttl)


def rate_limit_check(bucket: str, limit: int, window_seconds: int = 60) -> bool:
    """Simple fixed-window rate limiter. Returns True if under the limit."""
    r = get_redis_client()
    key = f"thos:ratelimit:{bucket}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, window_seconds)
    return count <= limit
