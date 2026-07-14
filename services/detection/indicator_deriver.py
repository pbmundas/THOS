"""
Detection indicator derivation — turns a hunting hypothesis + MITRE
ATT&CK context into concrete detection indicators (relevant event IDs
and keyword substrings) via the LLM, instead of a hardcoded
technique-id -> indicator lookup table.

This mirrors the same pattern already used by
services/hunting/query_generator.py for SIEM query generation: ask the
model, grounded in the actual hypothesis/technique context for THIS
hunt, rather than encode static domain knowledge in Python that only
covers a handful of techniques and goes stale the moment a new
technique or tool variant shows up.
"""
import json
import asyncio
from services.siem.clients import ollama_generate
from services.observability import cache

SYSTEM_PROMPT = (
    "You are a SOC detection engineering assistant. You are given a "
    "hunting hypothesis and its MITRE ATT&CK technique/tactic context. "
    "Produce ONLY a JSON object with two keys:\n"
    '{"event_ids": ["<Windows Security or Sysmon Event ID(s) most relevant '
    'to detecting this specific activity>"], '
    '"keywords": ["<short substrings, tool names, DLL names, or command '
    'fragments that would literally appear in a raw log line as evidence '
    'of this activity>"]}\n'
    "Base these on your own security knowledge of this technique. Only "
    "include an event ID or keyword you are reasonably confident is "
    "actually associated with this specific technique — it is fine, and "
    "preferred, to return a shorter list or an empty list for either "
    "field rather than guess. No markdown fences, no commentary — JSON "
    "only."
)


def _parse(raw: str) -> dict:
    cleaned = raw.strip().strip("`").strip()
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {}


async def derive_indicators(hypothesis_text: str, technique_id: str = "",
                             technique_name: str = "", tactic: str = "") -> dict:
    """Ask the LLM (not a static table) which event IDs and keywords are
    actually relevant to detecting the given hypothesis/technique."""
    cache_key = f"v2|{technique_id}|{technique_name}|{tactic}"
    cached = await asyncio.to_thread(cache.cache_get, "indicators", cache_key)
    if isinstance(cached, dict):
        return cached
    prompt = (
        f"Hypothesis: {hypothesis_text}\n"
        f"MITRE technique: {technique_id} ({technique_name}) — tactic: {tactic}\n\n"
        f"Generate the JSON now."
    )
    try:
        raw = await ollama_generate(prompt=prompt, system=SYSTEM_PROMPT, agent="indicator_deriver")
    except Exception:
        # Keep deterministic SigmaHQ/THOS rule evaluation available when the
        # optional indicator model is slow or offline.
        raw = ""
    parsed = _parse(raw)

    event_ids = [str(e).strip() for e in parsed.get("event_ids", []) if str(e).strip()]
    keywords = [str(k).strip().lower() for k in parsed.get("keywords", []) if str(k).strip()]

    result = {"event_ids": event_ids, "keywords": keywords}
    if event_ids or keywords:
        await asyncio.to_thread(cache.cache_set, "indicators", cache_key, result, ttl=86400)
    return result
