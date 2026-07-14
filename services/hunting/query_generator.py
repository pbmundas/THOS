"""
Query generator tool — turns a hunting hypothesis into a concrete SIEM
query, grounded in the SIEM-KB field mapping so the LLM doesn't
hallucinate field names.
"""
import asyncio

from services.siem.clients import ollama_generate
from services.siem.siem_kb import get_field_mapping
from services.observability import cache

SYSTEM_PROMPT = (
    "You are a SOC threat hunting query generation assistant. "
    "You are given a hunting hypothesis and a mapping of normalized "
    "field names to the exact field names used by the target SIEM. "
    "Produce ONLY a single valid query string for that SIEM's query "
    "language. Do not include explanation, markdown, or commentary."
)

# "folder" hunts run against locally parsed log files rather than a live
# SIEM query API, so instead of vendor query syntax we want a short list
# of relevant keywords/entities (process names, event types, usernames,
# suspicious terms) that file_log_parser can substring-match against
# every normalized record.
FOLDER_SYSTEM_PROMPT = (
    "You are a SOC threat hunting assistant helping search a folder of "
    "raw log files (EVTX, syslog, CSV, CEF, JSON/ECS, XML, pcap, etc.) "
    "that have already been parsed into generic records with fields like "
    "timestamp, host, user, event, src_ip, dst_ip, and detail. "
    "Given a hunting hypothesis, produce ONLY a comma-separated list of "
    "3-8 short keywords or entity names (process names, event types, "
    "usernames, ports, protocols, suspicious strings) that would help "
    "find log records relevant to this hypothesis via substring "
    "matching. Do not include explanation, markdown, numbering, or "
    "commentary — just the comma-separated keyword list."
)

FOLDER_SIEM_TYPES = {"folder", "local_folder", "file", "local"}


def _fallback_query(hypothesis_text: str, siem_type: str) -> str:
    """Provide a safe, visible degraded-mode query when a local model is unavailable.

    The folder connector already falls back to an unfiltered scan when these
    terms produce no hits, so this is safer than silently returning an empty
    query and falsely implying that an LLM query was generated.
    """
    terms = []
    for token in hypothesis_text.replace("/", " ").replace("-", " ").split():
        cleaned = "".join(char for char in token if char.isalnum() or char == ".")
        if len(cleaned) >= 4 and cleaned.lower() not in {"attackers", "activity", "detecting", "below"}:
            terms.append(cleaned.lower())
        if len(terms) == 6:
            break
    return ", ".join(terms) if siem_type.lower() in FOLDER_SIEM_TYPES else "*"


def _normalize_folder_query(value: str, hypothesis_text: str) -> str:
    """Accept only a compact keyword list, never model explanation prose."""
    candidate = (value or "").strip().splitlines()[0] if value else ""
    if len(candidate) > 180 or any(marker in candidate.lower() for marker in ("here", "query", "keyword", "because", ":")):
        return _fallback_query(hypothesis_text, "folder")
    terms = [term.strip().strip("'\"") for term in candidate.split(",")]
    terms = [term for term in terms if 1 < len(term) <= 48 and all(ch.isalnum() or ch in ".-_\\/" for ch in term)]
    return ", ".join(terms[:8]) if terms else _fallback_query(hypothesis_text, "folder")


async def generate_query(hypothesis_text: str, siem_type: str = "mock") -> dict:
    # cache.py's own docstring calls this out as a target ("repeated SIEM
    # queries and LLM calls") but nothing called it — a hunter iterating on
    # the same hypothesis/SIEM combo redid the full LLM query-gen call
    # every time. Cache key is exactly the (siem_type, hypothesis_text)
    # pair that determines the output.
    cache_payload = f"{siem_type}|{hypothesis_text}"
    cached_query = await asyncio.to_thread(cache.cache_get, "query_gen", cache_payload)
    if isinstance(cached_query, str) and cached_query.strip():
        return {
            "siem_type": siem_type,
            "hypothesis": hypothesis_text,
            "query": cached_query,
        }

    field_map = get_field_mapping(siem_type) or {"note": "no field map available — use generic field names"}

    if siem_type.lower() in FOLDER_SIEM_TYPES:
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Normalized fields available: {field_map}\n\n"
            f"Generate the keyword list now."
        )
        try:
            query_text = await ollama_generate(prompt=prompt, system=FOLDER_SYSTEM_PROMPT, agent="query_gen")
        except Exception:
            query_text = ""
    else:
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Target SIEM: {siem_type}\n"
            f"Field mapping: {field_map}\n\n"
            f"Generate the query now."
        )
        try:
            query_text = await ollama_generate(prompt=prompt, system=SYSTEM_PROMPT, agent="query_gen")
        except Exception:
            query_text = ""

    query_text = query_text.strip() or _fallback_query(hypothesis_text, siem_type)
    if siem_type.lower() in FOLDER_SIEM_TYPES:
        query_text = _normalize_folder_query(query_text, hypothesis_text)
    await asyncio.to_thread(cache.cache_set, "query_gen", cache_payload, query_text)

    return {
        "siem_type": siem_type,
        "hypothesis": hypothesis_text,
        "query": query_text,
    }
