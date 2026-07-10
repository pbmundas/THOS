"""
LangGraph node: refresh the HEARTH hypothesis KB from the live GitHub repo
before each hunt, at most once per REFRESH_TTL_SECONDS (default 1 hour) —
so hunters always get reasonably-fresh hypotheses without every single hunt
paying the cost of a GitHub fetch + re-embedding ~270 documents.

Uses the existing cache_lookup/cache_store MCP tools (Redis-backed) purely
as a "have we refreshed recently?" flag; the actual refresh work happens
via the refresh_hearth_hypotheses MCP tool.
"""
import logging
import os

from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState

logger = logging.getLogger(__name__)

REFRESH_TTL_SECONDS = int(os.environ.get("HEARTH_REFRESH_TTL_SECONDS", "3600"))
_CACHE_NAMESPACE = "hearth_kb_refresh"
_CACHE_KEY = "last_refresh"


async def refresh_hearth_kb_node(state: HuntState) -> dict:
    """Best-effort: never fails the hunt if GitHub is unreachable or the
    refresh errors out — this is a freshness nicety, not a hard dependency."""
    try:
        cached = await call_tool("cache_lookup", {"namespace": _CACHE_NAMESPACE, "payload": _CACHE_KEY})
        if cached and cached.get("hit"):
            return {}  # refreshed recently enough, skip

        result = await call_tool("refresh_hearth_hypotheses", {})
        if result.get("refreshed"):
            await call_tool(
                "cache_store",
                {
                    "namespace": _CACHE_NAMESPACE,
                    "payload": _CACHE_KEY,
                    "value": {"count": result.get("count", 0)},
                    "ttl_seconds": REFRESH_TTL_SECONDS,
                },
            )
    except Exception:  # noqa: BLE001 - never block a hunt on KB refresh issues
        logger.warning("refresh_hearth_kb_node skipped", exc_info=True)

    return {}
