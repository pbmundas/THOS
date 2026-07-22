"""Bounded on-prem chat agent with a read-only MCP tool allowlist."""
from __future__ import annotations

import asyncio
import json
import logging

from services.mcp.mcp_client import call_tool
from services.reasoning.ollama_client import generate

logger = logging.getLogger(__name__)
CHAT_MODEL_ATTEMPTS = 3

TOOL_DESCRIPTIONS = {
    "search_knowledge_base": "Search analyst-uploaded organizational documents. args: query, n_results",
    "search_hypotheses_semantic": "Find relevant HEARTH hunting hypotheses. args: query, n_results",
    "list_hearth_hypotheses": "List hypotheses, optionally by tactic. args: tactic",
    "siem_field_mapping": "Read normalized-to-vendor SIEM fields. args: siem_type",
    "list_log_source_files": "List supported evidence files in an allowed server folder. args: folder",
}
PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "tool_calls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": list(TOOL_DESCRIPTIONS)},
                    "arguments": {"type": "object"},
                },
                "required": ["name", "arguments"],
            },
            "maxItems": 4,
        },
    },
    "required": ["answer", "tool_calls"],
}
SYSTEM = """You are the THOS SOC assistant. You run fully on-premises. Be precise,
security-conscious, and concise. Use the supplied read-only MCP tools when the
question needs local hypotheses, RAG documents, SIEM schemas, or evidence-file
inventory. Never claim a tool ran unless its result is supplied. Do not invent
IOC evidence or authorize containment/detection promotion. Return only JSON."""


async def _generate_plan(prompt: str) -> dict:
    """Return one validated structured response, tolerating transient empty output."""
    reasons = []
    for attempt in range(1, CHAT_MODEL_ATTEMPTS + 1):
        try:
            raw = await generate(
                prompt,
                system=SYSTEM,
                format=PLAN_SCHEMA,
                agent="chat",
                transport_retries=1,
            )
            if not raw.strip():
                raise ValueError("model returned an empty response")
            plan = json.loads(raw)
            if not isinstance(plan, dict):
                raise ValueError("model response was not an object")
            answer = str(plan.get("answer", "")).strip()
            calls = plan.get("tool_calls", [])
            if not answer and not calls:
                raise ValueError("model returned neither an answer nor a tool request")
            return plan
        except Exception as exc:  # noqa: BLE001 - bounded model strike handling
            reasons.append(f"attempt {attempt}: {exc}")
            logger.warning("chat model strike %s/%s: %s", attempt, CHAT_MODEL_ATTEMPTS, exc)
    raise RuntimeError("chat model failed after three attempts: " + "; ".join(reasons))


async def chat(message: str, history: list[dict], analyst: str) -> dict:
    recent = [
        {"role": item.get("role"), "content": str(item.get("content", ""))[:8_000]}
        for item in history[-16:]
        if item.get("role") in {"user", "assistant"} and str(item.get("content", "")).strip()
    ]
    prompt = (
        f"Analyst: {analyst}\nAvailable MCP tools:\n"
        + "\n".join(f"- {name}: {description}" for name, description in TOOL_DESCRIPTIONS.items())
        + f"\n\nRecent conversation:\n{json.dumps(recent, ensure_ascii=False)}"
        + f"\n\nCurrent request:\n{message}"
        + "\n\nReturn an answer and zero or more required tool_calls."
    )
    plan = await _generate_plan(prompt)
    calls = [item for item in plan.get("tool_calls", []) if item.get("name") in TOOL_DESCRIPTIONS][:4]
    if not calls:
        return {"answer": str(plan.get("answer", "")).strip(), "tools_used": []}

    results = await asyncio.gather(*[
        call_tool(item["name"], item.get("arguments") or {}) for item in calls
    ], return_exceptions=True)
    evidence = []
    for item, result in zip(calls, results):
        evidence.append({
            "tool": item["name"],
            "arguments": item.get("arguments") or {},
            "result": {"error": str(result)} if isinstance(result, Exception) else result,
        })
    final_prompt = (
        f"Recent conversation:\n{json.dumps(recent, ensure_ascii=False)}\n\n"
        f"Analyst request:\n{message}\n\nMCP tool results:\n"
        f"{json.dumps(evidence, ensure_ascii=False, default=str)[:50000]}\n\n"
        "Answer using these results. Clearly distinguish local evidence from general advice. "
        "Return tool_calls as an empty array."
    )
    final = await _generate_plan(final_prompt)
    return {"answer": str(final.get("answer", "")).strip(), "tools_used": [item["name"] for item in calls]}
