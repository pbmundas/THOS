from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState


async def generate_query_node(state: HuntState) -> dict:
    result = await call_tool(
        "generate_siem_query",
        {"hypothesis_text": state.get("hypothesis_text", ""), "siem_type": state.get("siem_type", "mock")},
    )
    return {
        "query": result.get("query", ""),
        "query_used_fallback": result.get("query_used_fallback", False),
        "query_validation_error": result.get("query_validation_error"),
    }
