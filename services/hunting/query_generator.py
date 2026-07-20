"""
Query generator tool — turns a hunting hypothesis into a concrete SIEM
query, grounded in the SIEM-KB field mapping so the LLM doesn't
hallucinate field names.
"""
import asyncio
import json

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

WAZUH_SYSTEM_PROMPT = (
    "You generate read-only OpenSearch Query DSL for Wazuh security events. "
    "Return ONLY one JSON object with exactly one top-level key named query. "
    "Use Wazuh fields such as @timestamp, agent.name, rule.id, "
    "rule.description, rule.groups, rule.mitre.id, decoder.name, location, "
    "full_log, data.srcip, data.dstip, data.srcuser, and data.dstuser. "
    "Do not use range or query_string queries, wildcard field names such as "
    "data.*, index names, size, sort, aggregations, scripts, markdown, or "
    "explanation. THOS adds the time range, target indices, and result cap."
)

WAZUH_TEXT_SEARCH_FIELDS = [
    "full_log^3", "rule.description^2", "rule.groups", "rule.mitre.id",
    "rule.mitre.technique", "agent.name", "decoder.name", "location",
]

_FALLBACK_STOP_WORDS = {
    "activity", "adversary", "attackers", "below", "detecting",
    "deploying", "discovery", "executing", "execution", "identify",
    "including", "known", "network", "performing", "service", "services",
    "such", "their", "tools", "using", "with",
}


def _fallback_query(hypothesis_text: str, siem_type: str) -> str:
    """Provide a safe, visible degraded-mode query when a local model is unavailable.

    The folder connector already falls back to an unfiltered scan when these
    terms produce no hits, so this is safer than silently returning an empty
    query and falsely implying that an LLM query was generated.
    """
    terms = []
    for token in hypothesis_text.replace("/", " ").replace("-", " ").split():
        cleaned = "".join(char for char in token if char.isalnum() or char == ".")
        lowered = cleaned.lower()
        if len(cleaned) >= 4 and lowered not in _FALLBACK_STOP_WORDS \
                and lowered not in terms:
            terms.append(lowered)
        if len(terms) == 8:
            break
    if siem_type.lower() in FOLDER_SIEM_TYPES:
        return ", ".join(terms)
    if siem_type.lower() == "wazuh":
        search = " ".join(terms) or "*"
        return json.dumps({
            "query": {
                "simple_query_string": {
                    "query": search,
                    "fields": WAZUH_TEXT_SEARCH_FIELDS,
                    # A degraded-mode retrieval query should surface candidate
                    # evidence for later AI analysis, not require every
                    # extracted indicator to occur in one Wazuh document.
                    "default_operator": "or",
                }
            }
        }, separators=(",", ":"))
    return "*"


def _normalize_folder_query(value: str, hypothesis_text: str) -> str:
    """Accept only a compact keyword list, never model explanation prose."""
    candidate = (value or "").strip().splitlines()[0] if value else ""
    if len(candidate) > 180 or any(marker in candidate.lower() for marker in ("here", "query", "keyword", "because", ":")):
        return _fallback_query(hypothesis_text, "folder")
    terms = [term.strip().strip("'\"") for term in candidate.split(",")]
    terms = [term for term in terms if 1 < len(term) <= 48 and all(ch.isalnum() or ch in ".-_\\/" for ch in term)]
    return ", ".join(terms[:8]) if terms else _fallback_query(hypothesis_text, "folder")


def _normalize_wazuh_query(value: str, hypothesis_text: str) -> str:
    """Keep only a JSON query object; connector-side validation is authoritative."""
    candidate = (value or "").strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        candidate = "\n".join(lines).strip()
    try:
        payload = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return _fallback_query(hypothesis_text, "wazuh")
    if not isinstance(payload, dict):
        return _fallback_query(hypothesis_text, "wazuh")
    clause = payload.get("query", payload)
    if not isinstance(clause, dict):
        return _fallback_query(hypothesis_text, "wazuh")
    # The connector is authoritative, but rejecting these common model errors
    # here lets us fall back to hypothesis keywords instead of failing a hunt.
    def contains_disallowed(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() in {"range", "query_string"}:
                    return True
                if str(key).lower() in {"simple_query_string", "multi_match"} \
                        and isinstance(child, dict):
                    fields = child.get("fields", [])
                    if not isinstance(fields, list) or any(
                        not isinstance(field, str) or "*" in field
                        for field in fields
                    ):
                        return True
                if contains_disallowed(child):
                    return True
        elif isinstance(item, list):
            return any(contains_disallowed(child) for child in item)
        return False

    if contains_disallowed(clause):
        return _fallback_query(hypothesis_text, "wazuh")
    return json.dumps({"query": clause}, separators=(",", ":"), ensure_ascii=False)


async def generate_query(hypothesis_text: str, siem_type: str = "mock") -> dict:
    # cache.py's own docstring calls this out as a target ("repeated SIEM
    # queries and LLM calls") but nothing called it — a hunter iterating on
    # the same hypothesis/SIEM combo redid the full LLM query-gen call
    # every time. Cache key is exactly the (siem_type, hypothesis_text)
    # pair that determines the output.
    # v2 invalidates Wazuh queries cached before heterogeneous data.* fields
    # and model-supplied ranges were rejected.
    cache_version = "v2" if siem_type.lower() == "wazuh" else "v1"
    cache_payload = f"{cache_version}|{siem_type}|{hypothesis_text}"
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
    elif siem_type.lower() == "wazuh":
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Wazuh field mapping: {field_map}\n\n"
            "Generate the JSON Query DSL now."
        )
        try:
            query_text = await ollama_generate(
                prompt=prompt, system=WAZUH_SYSTEM_PROMPT, agent="query_gen"
            )
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
    elif siem_type.lower() == "wazuh":
        query_text = _normalize_wazuh_query(query_text, hypothesis_text)
    await asyncio.to_thread(cache.cache_set, "query_gen", cache_payload, query_text)

    return {
        "siem_type": siem_type,
        "hypothesis": hypothesis_text,
        "query": query_text,
    }
