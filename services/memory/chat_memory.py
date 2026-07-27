"""Temporary, analyst-scoped multi-conversation memory backed by Redis."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import uuid

from services.siem.clients import get_redis_client


CHAT_TTL_SECONDS = max(900, int(os.environ.get("CHAT_MEMORY_TTL_SECONDS", "43200")))
MAX_MESSAGES = max(10, int(os.environ.get("CHAT_MEMORY_MAX_MESSAGES", "60")))
_SAFE_ID = re.compile(r"^[0-9a-f]{32}$")


def _analyst(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value or "analyst")[:80]


def _conversation_key(analyst: str, conversation_id: str) -> str:
    return f"thos:chat:{_analyst(analyst)}:{conversation_id}"


def _index_key(analyst: str) -> str:
    return f"thos:chat:index:{_analyst(analyst)}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_message(message: dict) -> dict | None:
    role = str(message.get("role", ""))
    content = str(message.get("content", "")).strip()
    if role not in {"user", "assistant"} or not content:
        return None
    cleaned = {"role": role, "content": content[:32_000]}
    tools = message.get("tools")
    if isinstance(tools, list):
        cleaned["tools"] = [str(item)[:120] for item in tools[:8]]
    sources = message.get("sources")
    if isinstance(sources, list):
        cleaned["sources"] = [
            {
                "id": str(item.get("id", ""))[:80],
                "title": str(item.get("title", ""))[:160],
                "source": str(item.get("source", ""))[:500],
            }
            for item in sources[:8]
            if isinstance(item, dict) and item.get("id")
        ]
    agents = message.get("agents")
    if isinstance(agents, list):
        cleaned["agents"] = [
            {
                "agent_id": str(item.get("agent_id", ""))[:120],
                "agent_name": str(item.get("agent_name", ""))[:160],
                "model_tier": str(item.get("model_tier", ""))[:40],
                "model_name": str(item.get("model_name", ""))[:160],
                "duration_ms": max(0, int(item.get("duration_ms") or 0)),
            }
            for item in agents[:8]
            if isinstance(item, dict) and item.get("agent_name")
        ]
    if message.get("error"):
        cleaned["error"] = True
    cleaned["created_at"] = str(message.get("created_at") or _now())
    return cleaned


def create_conversation(analyst: str, title: str = "New conversation") -> dict:
    conversation_id = uuid.uuid4().hex
    now = _now()
    conversation = {
        "id": conversation_id,
        "title": (title or "New conversation").strip()[:120],
        "messages": [],
        "created_at": now,
        "updated_at": now,
    }
    save_conversation(analyst, conversation)
    return conversation


def save_conversation(analyst: str, conversation: dict) -> dict:
    conversation_id = str(conversation.get("id", ""))
    if not _SAFE_ID.fullmatch(conversation_id):
        raise ValueError("invalid conversation id")
    messages = [item for item in (_clean_message(message) for message in conversation.get("messages", [])) if item]
    normalized = {
        "id": conversation_id,
        "title": str(conversation.get("title") or "New conversation").strip()[:120],
        "messages": messages[-MAX_MESSAGES:],
        "created_at": str(conversation.get("created_at") or _now()),
        "updated_at": _now(),
    }
    client = get_redis_client()
    timestamp = datetime.now(timezone.utc).timestamp()
    pipeline = client.pipeline()
    pipeline.set(_conversation_key(analyst, conversation_id), json.dumps(normalized), ex=CHAT_TTL_SECONDS)
    pipeline.zadd(_index_key(analyst), {conversation_id: timestamp})
    pipeline.expire(_index_key(analyst), CHAT_TTL_SECONDS)
    pipeline.execute()
    return normalized


def get_conversation(analyst: str, conversation_id: str) -> dict | None:
    if not _SAFE_ID.fullmatch(conversation_id or ""):
        return None
    client = get_redis_client()
    raw = client.get(_conversation_key(analyst, conversation_id))
    if not raw:
        client.zrem(_index_key(analyst), conversation_id)
        return None
    try:
        conversation = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        delete_conversation(analyst, conversation_id)
        return None
    client.expire(_conversation_key(analyst, conversation_id), CHAT_TTL_SECONDS)
    client.expire(_index_key(analyst), CHAT_TTL_SECONDS)
    return conversation if isinstance(conversation, dict) else None


def list_conversations(analyst: str) -> list[dict]:
    client = get_redis_client()
    ids = client.zrevrange(_index_key(analyst), 0, 49)
    items = []
    for conversation_id in ids:
        conversation = get_conversation(analyst, conversation_id)
        if conversation:
            items.append({key: conversation.get(key) for key in ("id", "title", "created_at", "updated_at")})
    return items


def append_message(analyst: str, conversation_id: str, message: dict) -> dict:
    conversation = get_conversation(analyst, conversation_id)
    if conversation is None:
        raise KeyError("conversation not found")
    cleaned = _clean_message(message)
    if cleaned is None:
        raise ValueError("message must contain a supported role and non-empty content")
    conversation.setdefault("messages", []).append(cleaned)
    if conversation.get("title") == "New conversation" and cleaned["role"] == "user":
        conversation["title"] = cleaned["content"].replace("\n", " ")[:72]
    return save_conversation(analyst, conversation)


def delete_conversation(analyst: str, conversation_id: str) -> bool:
    if not _SAFE_ID.fullmatch(conversation_id or ""):
        return False
    client = get_redis_client()
    removed = client.delete(_conversation_key(analyst, conversation_id))
    client.zrem(_index_key(analyst), conversation_id)
    return bool(removed)
