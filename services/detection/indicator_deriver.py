"""Grounded detection-indicator derivation for one hunt."""
from __future__ import annotations

import asyncio
import json

from services.knowledge.cyber_retrieval import search as search_cyber_knowledge
from services.observability import cache
from services.reasoning.ollama_client import generate
from services.runtime_config import get_value


SYSTEM_PROMPT = (
    "You are a SOC detection engineering assistant. You are given a hunting "
    "hypothesis, MITRE ATT&CK context, and governed reference excerpts. "
    "Produce ONLY a JSON object with three keys:\n"
    '{"event_ids": ["<literal Windows Security or Sysmon Event ID>"], '
    '"keywords": ["<literal short substring, tool, DLL, file, or command '
    'fragment>"], "behavior_phrases": ["<short literal behavior fragment, '
    'protocol action, alert label, or telemetry pattern>"]}\n'
    "Use only literal values present in the supplied hypothesis or governed "
    "reference excerpts. Do not use model memory to introduce an event ID, "
    "tool name, file, DLL, command, or other indicator. Return an empty list "
    "rather than infer or guess. Behavior phrases should be concise fragments "
    "that could occur in telemetry, such as a protocol action stated by the "
    "hypothesis, not a conclusion that an attack occurred. No markdown fences "
    "or commentary; JSON only."
)

INDICATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "event_ids": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 30,
        },
        "keywords": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 50,
        },
        "behavior_phrases": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 30,
        },
    },
    "required": ["event_ids", "keywords", "behavior_phrases"],
    "additionalProperties": False,
}


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


async def derive_indicators(
    hypothesis_text: str,
    technique_id: str = "",
    technique_name: str = "",
    tactic: str = "",
) -> dict:
    """Return only model-selected indicators that pass literal grounding."""
    cache_key = (
        f"v4|{technique_id}|{technique_name}|{tactic}|{hypothesis_text}"
    )
    cached = await asyncio.to_thread(cache.cache_get, "indicators", cache_key)
    if isinstance(cached, dict):
        return cached

    try:
        reference_hit_cap = max(
            1,
            int(get_value("autonomy", "indicator_reference_hit_cap", default=3)),
        )
        reference_hits = await asyncio.to_thread(
            search_cyber_knowledge,
            f"{technique_id} {technique_name} {hypothesis_text}",
            reference_hit_cap,
            ["detection", "threat_hunting", "dfir", "mitre_attack"],
        )
    except Exception:
        reference_hits = []
    reference_char_cap = max(
        512,
        int(get_value("autonomy", "indicator_reference_char_cap", default=2400)),
    )
    reference_text = "\n".join(
        f"[{hit.get('citation_id', 'unverified')}] {hit.get('text', '')}"
        for hit in reference_hits
        if isinstance(hit, dict)
    )[:reference_char_cap]
    prompt = (
        f"Hypothesis: {hypothesis_text}\n"
        f"MITRE technique: {technique_id} ({technique_name}); tactic: {tactic}\n\n"
        f"Governed reference excerpts:\n{reference_text or '(none available)'}\n\n"
        "Generate the JSON now."
    )
    try:
        raw = await generate(
            prompt=prompt,
            system=SYSTEM_PROMPT,
            format=INDICATOR_SCHEMA,
            agent="indicator_deriver",
            transport_retries=max(
                0,
                int(get_value("autonomy", "indicator_transport_retries", default=0)),
            ),
            num_predict=max(
                64,
                int(get_value("autonomy", "indicator_decision_num_predict", default=192)),
            ),
            timeout_seconds=max(
                1,
                float(
                    get_value(
                        "autonomy",
                        "indicator_generation_timeout_seconds",
                        default=45,
                    )
                ),
            ),
        )
    except Exception:
        raw = ""
    parsed = _parse(raw)

    grounding_text = f"{hypothesis_text}\n{reference_text}".lower()
    event_ids = list(dict.fromkeys(
        str(value).strip()
        for value in parsed.get("event_ids", [])
        if str(value).strip()
        and str(value).strip().lower() in grounding_text
    ))[:30]
    keywords = list(dict.fromkeys(
        str(value).strip().lower()
        for value in parsed.get("keywords", [])
        if str(value).strip()
        and str(value).strip().lower() in grounding_text
    ))[:50]
    behavior_phrases = list(dict.fromkeys(
        str(value).strip().lower()
        for value in parsed.get("behavior_phrases", [])
        if len(str(value).strip()) >= 5
        and str(value).strip().lower() in grounding_text
    ))[:30]
    result = {
        "event_ids": event_ids,
        "keywords": keywords,
        "behavior_phrases": behavior_phrases,
        "grounding_sources": [
            hit.get("citation_id")
            for hit in reference_hits
            if isinstance(hit, dict) and hit.get("citation_id")
        ],
    }
    if event_ids or keywords or behavior_phrases:
        await asyncio.to_thread(
            cache.cache_set,
            "indicators",
            cache_key,
            result,
            ttl=86400,
        )
    return result
