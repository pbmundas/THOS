"""
Thin wrapper around the FastMCP client so LangGraph nodes can call
tools with a single `await call_tool("tool_name", {...})` line without
each node worrying about connection setup.

A single streamable-HTTP session is opened lazily and reused across every
tool call in the process, instead of opening/tearing down a brand-new
Client(MCP_SERVER_URL) session per call (~10-15 times per hunt). An
asyncio.Lock guards lazy connect/reconnect so concurrent hunts in the same
event loop don't race to open duplicate sessions, and a single retry with
a fresh session covers the case where the server has dropped a stale
connection.
"""
import os
import json
import logging
import asyncio
from fastmcp import Client

logger = logging.getLogger(__name__)

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://mcp-server:8100/mcp")

# Must match the MCP server's MCP_AUTH_TOKEN (see services/api/server.py) —
# the server now requires a bearer token on every call, so an unauthenticated
# caller can no longer reach any SOC tool directly.
_DEFAULT_MCP_AUTH_TOKEN = "thos_change_me_mcp_token"
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", _DEFAULT_MCP_AUTH_TOKEN)
if MCP_AUTH_TOKEN == _DEFAULT_MCP_AUTH_TOKEN:
    logger.warning(
        "MCP_AUTH_TOKEN is unset, using the built-in default. Set a real "
        "shared secret before exposing this stack beyond a trusted local "
        "dev network."
    )

_client: Client | None = None
_client_lock = asyncio.Lock()


def _unwrap(result):
    # FastMCP returns content blocks; unwrap to plain python data
    if hasattr(result, "data"):
        return result.data
    if isinstance(result, list) and result:
        block = result[0]
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return result


async def _get_client() -> Client:
    global _client
    async with _client_lock:
        if _client is None:
            client = Client(MCP_SERVER_URL, auth=MCP_AUTH_TOKEN)
            await client.__aenter__()
            _client = client
        return _client


async def _reset_client():
    global _client
    async with _client_lock:
        stale = _client
        _client = None
    if stale is not None:
        try:
            await stale.__aexit__(None, None, None)
        except Exception:
            pass


async def call_tool(tool_name: str, arguments: dict):
    client = await _get_client()
    try:
        result = await client.call_tool(tool_name, arguments)
    except Exception:
        # Session may have gone stale (server restart, idle timeout, etc.) —
        # reconnect once and retry before giving up.
        await _reset_client()
        client = await _get_client()
        result = await client.call_tool(tool_name, arguments)
    return _unwrap(result)


async def list_tools():
    client = await _get_client()
    try:
        return await client.list_tools()
    except Exception:
        await _reset_client()
        client = await _get_client()
        return await client.list_tools()


async def close():
    """Call during app shutdown to cleanly tear down the shared session."""
    await _reset_client()
