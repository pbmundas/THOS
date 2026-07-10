"""
Shared retry/backoff helper for transient network failures.

Before this, no call site in the codebase retried anything: Ollama calls,
MCP calls, the GitHub HEARTH tarball fetch, and the LogRhythm client all
failed outright on the first dropped connection, timeout, or momentary
5xx — exactly the class of error a short retry with backoff recovers
from for free. Two flavors are provided since the codebase mixes async
httpx.AsyncClient calls (Ollama, MCP) with sync httpx.Client calls
(LogRhythm, the GitHub tarball fetch).

Deliberately narrow about what's retried: connection drops, timeouts,
and 5xx server errors are retried; 4xx errors are not (a bad API token
or malformed request won't fix itself on attempt two — retrying those
just delays a real failure and can trip provider rate limits harder).
"""
import asyncio
import time
import random
import logging

import httpx

logger = logging.getLogger("thos.retry")

_RETRYABLE_EXC = (httpx.TransportError, httpx.TimeoutException)


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, _RETRYABLE_EXC):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response is not None and exc.response.status_code >= 500
    return False


def _backoff_delay(attempt: int, base_delay: float, max_delay: float) -> float:
    delay = min(max_delay, base_delay * (2 ** attempt))
    # Jitter so a batch of concurrent hunts retrying the same downstream
    # outage don't all hammer it again in lockstep.
    return delay * (0.5 + random.random())


async def async_retry(fn, *args, retries: int = 3, base_delay: float = 0.5,
                       max_delay: float = 8.0, what: str = "call", **kwargs):
    """Retry an async callable on transient network errors with exponential
    backoff + jitter. Re-raises the triggering error once retries are
    exhausted, or immediately for a non-retryable error."""
    for attempt in range(retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 - re-raised below when appropriate
            if not _is_retryable(e) or attempt == retries:
                raise
            delay = _backoff_delay(attempt, base_delay, max_delay)
            logger.warning(
                "[retry] %s failed (attempt %d/%d): %s — retrying in %.1fs",
                what, attempt + 1, retries + 1, e, delay,
            )
            await asyncio.sleep(delay)


def sync_retry(fn, *args, retries: int = 3, base_delay: float = 0.5,
                max_delay: float = 8.0, what: str = "call", **kwargs):
    """Sync counterpart of async_retry, for httpx.Client-based callers
    (e.g. the LogRhythm connector) that can't use asyncio.sleep."""
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 - re-raised below when appropriate
            if not _is_retryable(e) or attempt == retries:
                raise
            delay = _backoff_delay(attempt, base_delay, max_delay)
            logger.warning(
                "[retry] %s failed (attempt %d/%d): %s — retrying in %.1fs",
                what, attempt + 1, retries + 1, e, delay,
            )
            time.sleep(delay)
