"""
Query generator tool — turns a hunting hypothesis into a concrete SIEM
query, grounded in the SIEM-KB field mapping so the LLM doesn't
hallucinate field names.
"""
import asyncio
import json
import re

from services.siem.clients import ollama_generate
from services.siem.siem_kb import get_field_mapping
from services.observability import cache
from services.reasoning.model_router import target_for

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
    "such", "their", "tools", "using", "with", "often", "utilize",
    "powerful", "scripting", "language", "available", "windows", "system",
    "systems", "crucial", "detailed", "provide", "presence", "attempting",
}

_EXPLICIT_EVENT_ID = re.compile(r"\b(?:event\s*id|eventid)[\s:_-]*(\d{1,6})\b", re.IGNORECASE)
_EXPLICIT_ARTIFACT = re.compile(
    r"\b[a-zA-Z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|msi)\b",
    re.IGNORECASE,
)


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
    if siem_type.lower() == "splunk":
        # The connector deterministically normalizes this to ``search *``.
        return "*"
    if siem_type.lower() == "qradar":
        # AQL has no universally safe free-text field across deployments.
        # A bounded SELECT is syntactically valid and the connector adds the
        # configured time window and LIMIT deterministically.
        return "SELECT * FROM events"
    if siem_type.lower() == "logrhythm":
        return " ".join(terms) or "*"
    return "*"


def _balanced_query_syntax(value: str) -> bool:
    """Conservative quote/bracket check shared by text query dialects."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote = None
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return False
    return quote is None and not stack


def _validate_text_query(candidate: str, siem_type: str) -> str:
    if not candidate or len(candidate) > 8_000:
        raise ValueError("query is empty or exceeds 8,000 characters")
    lowered = candidate.lower()
    if "```" in candidate or any(ord(char) < 32 and char not in "\t\r\n" for char in candidate):
        raise ValueError("query contains markdown or control characters")
    if not _balanced_query_syntax(candidate):
        raise ValueError("query has unbalanced quotes or brackets")
    if siem_type == "splunk" and re.search(
        r"(?:^|\|)\s*(?:delete|collect|outputlookup|sendemail|script)\b", lowered
    ):
        raise ValueError("SPL query contains a state-changing command")
    if siem_type == "qradar":
        statement = candidate.strip().rstrip(";").strip()
        if ";" in statement:
            raise ValueError("AQL must contain exactly one statement")
        if not re.match(r"^select\b", statement, re.IGNORECASE):
            raise ValueError("AQL must be a complete SELECT statement")
        if not re.search(r"\bfrom\s+(?:events|flows)\b", statement, re.IGNORECASE):
            raise ValueError("AQL SELECT must read from events or flows")
        if re.search(r"\b(?:into|insert|update|delete|drop|alter)\b", statement, re.IGNORECASE):
            raise ValueError("AQL query must be read-only")
        return statement
    return candidate.strip()


def _normalize_folder_query(value: str, hypothesis_text: str) -> str:
    """Accept only a compact keyword list, never model explanation prose."""
    candidate = (value or "").strip().splitlines()[0] if value else ""
    if len(candidate) > 180 or any(marker in candidate.lower() for marker in ("here", "query", "keyword", "because", ":")):
        return _fallback_query(hypothesis_text, "folder")
    raw_terms = [term.strip().strip("'\"") for term in candidate.split(",")]
    terms = []
    for term in raw_terms:
        lowered = term.lower()
        if lowered in _FALLBACK_STOP_WORDS:
            continue
        if 1 < len(term) <= 48 and all(ch.isalnum() or ch in ".-_\\/" for ch in term):
            if lowered not in {existing.lower() for existing in terms}:
                terms.append(term)

    # Model keyword lists sometimes start with generic prose words. Preserve
    # only high-signal terms, then deterministically add indicators stated
    # explicitly in the hypothesis (event IDs and executable/script names).
    for explicit in (
        list(_EXPLICIT_EVENT_ID.findall(hypothesis_text))
        + list(_EXPLICIT_ARTIFACT.findall(hypothesis_text))
    ):
        if explicit.lower() not in {term.lower() for term in terms}:
            terms.append(explicit)
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


def validate_and_normalize_query(value: str, hypothesis_text: str,
                                 siem_type: str) -> dict:
    """Deterministically validate a model query and retry with a safe fallback.

    This function performs no model call. It is used both after query
    generation and immediately before execution, so reasoning-generated
    follow-up queries cannot bypass the syntax/read-only checks.
    """
    dialect = (siem_type or "mock").lower()
    candidate = (value or "").strip()
    error = None
    try:
        if not candidate:
            raise ValueError("query generator returned an empty query")
        if dialect in FOLDER_SIEM_TYPES:
            normalized = _normalize_folder_query(candidate, hypothesis_text)
            if candidate and normalized == _fallback_query(hypothesis_text, "folder") \
                    and candidate != normalized:
                raise ValueError("folder query was not a compact keyword list")
        elif dialect == "wazuh":
            normalized = _normalize_wazuh_query(candidate, hypothesis_text)
            if candidate and normalized == _fallback_query(hypothesis_text, "wazuh") \
                    and candidate != normalized:
                raise ValueError("Wazuh query was not valid, bounded Query DSL")
        elif dialect in {"splunk", "qradar", "logrhythm"}:
            normalized = _validate_text_query(candidate, dialect)
        else:
            normalized = candidate or _fallback_query(hypothesis_text, dialect)
    except ValueError as exc:
        error = str(exc)
        normalized = _fallback_query(hypothesis_text, dialect)
        # The deterministic retry is itself checked. A bad built-in fallback
        # is a programming error and must never reach a live SIEM silently.
        if dialect in {"splunk", "qradar", "logrhythm"}:
            normalized = _validate_text_query(normalized, dialect)
        elif dialect == "wazuh":
            json.loads(normalized)
    return {
        "query": normalized,
        "used_fallback": error is not None,
        "validation_error": error,
    }


async def generate_query(hypothesis_text: str, siem_type: str = "mock") -> dict:
    # cache.py's own docstring calls this out as a target ("repeated SIEM
    # queries and LLM calls") but nothing called it — a hunter iterating on
    # the same hypothesis/SIEM combo redid the full LLM query-gen call
    # every time. Cache key is exactly the (siem_type, hypothesis_text)
    # pair that determines the output.
    # v2 invalidates Wazuh queries cached before heterogeneous data.* fields
    # and model-supplied ranges were rejected.
    field_map = get_field_mapping(siem_type) or {"note": "no field map available — use generic field names"}
    # The uploaded field inventory changes valid query syntax, so it is part
    # of the cache key. A schema upload invalidates only affected query-gen
    # entries without flushing unrelated hypotheses.
    cache_version = "v5"
    field_signature = json.dumps(field_map, sort_keys=True, separators=(",", ":"))
    query_model = target_for("query_gen").model
    cache_payload = f"{cache_version}|{query_model}|{siem_type}|{field_signature}|{hypothesis_text}"
    cached_query = await asyncio.to_thread(cache.cache_get, "query_gen", cache_payload)
    if isinstance(cached_query, str) and cached_query.strip():
        validation = validate_and_normalize_query(cached_query, hypothesis_text, siem_type)
        return {
            "siem_type": siem_type,
            "hypothesis": hypothesis_text,
            "query": validation["query"],
            "query_used_fallback": validation["used_fallback"],
            "query_validation_error": validation["validation_error"],
        }

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

    validation = validate_and_normalize_query(query_text, hypothesis_text, siem_type)
    query_text = validation["query"]
    await asyncio.to_thread(cache.cache_set, "query_gen", cache_payload, query_text)

    return {
        "siem_type": siem_type,
        "hypothesis": hypothesis_text,
        "query": query_text,
        "query_used_fallback": validation["used_fallback"],
        "query_validation_error": validation["validation_error"],
    }
