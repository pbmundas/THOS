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
from services.runtime_config import get_value

SYSTEM_PROMPT = (
    "You are a senior SOC threat hunter generating one read-only query for "
    "one explicitly stated investigation step. You are given the hypothesis, "
    "the step objective, prior retrieval diagnostics when applicable, and a "
    "mapping of normalized field names to exact target-SIEM fields. Generate "
    "exactly one valid query in the named SIEM dialect. Use only mapped fields. "
    "A zero-result step should broaden only the stated constraints; a noisy "
    "step should tighten around literal entities, event categories, or the "
    "ATT&CK technique without inventing values. Do not add a time clause because "
    "THOS controls the bounded time window separately. Return only the query "
    "string with no explanation, markdown, or commentary."
)

# "folder" hunts run against locally parsed log files rather than a live
# SIEM query API, so instead of vendor query syntax we want a short list
# of relevant keywords/entities (process names, event types, usernames,
# suspicious terms) that file_log_parser can substring-match against
# every normalized record.
FOLDER_SYSTEM_PROMPT = (
    "You are a senior SOC threat hunter helping search a folder of "
    "raw log files (EVTX, syslog, CSV, CEF, JSON/ECS, XML, pcap, etc.) "
    "that have already been parsed into generic records with fields like "
    "timestamp, host, user, event, src_ip, dst_ip, and detail. "
    "Given a hunting hypothesis and one investigation-step objective, produce "
    "ONLY a comma-separated list of "
    "3-8 short keywords or entity names (process names, event types, "
    "usernames, ports, protocols, suspicious strings) that would help "
    "find log records relevant to this hypothesis via substring "
    "matching. Do not include explanation, markdown, numbering, or "
    "commentary — just the comma-separated keyword list."
)

FOLDER_SIEM_TYPES = {"folder", "local_folder", "file", "local"}

WAZUH_SYSTEM_PROMPT = (
    "You are a senior SOC threat hunter generating one read-only "
    "OpenSearch/Elasticsearch Query DSL query for the supplied investigation "
    "step and security-event field mapping. "
    "Return ONLY one JSON object with exactly one top-level key named query. "
    "Use only exact fields present in the supplied mapping or discovered field "
    "inventory. Cover every "
    "distinct evidence branch stated by the hypothesis that is representable "
    "in the supplied source schema; do not reduce a behavioral hypothesis to "
    "only its named tools or artifacts. Combine compatible branches with a "
    "bool/should query. Use match_phrase for text fields, term/terms for exact "
    "scalar fields, and exists for field presence. "
    "Do not use range or query_string queries, wildcard field names such as "
    "data.*, index names, size, sort, aggregations, scripts, markdown, or "
    "explanation. THOS adds the time range, target indices, and result cap."
)


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


def _normalize_folder_query(value: str) -> str:
    """Accept only a compact keyword list, never model explanation prose."""
    candidate = (value or "").strip().splitlines()[0] if value else ""
    if len(candidate) > 180 or any(marker in candidate.lower() for marker in ("here", "query", "keyword", "because", ":")):
        raise ValueError("folder query was not a compact keyword list")
    raw_terms = [term.strip().strip("'\"") for term in candidate.split(",")]
    terms = []
    for term in raw_terms:
        lowered = term.lower()
        if 1 < len(term) <= 48 and all(ch.isalnum() or ch in ".-_\\/" for ch in term):
            if lowered not in {existing.lower() for existing in terms}:
                terms.append(term)
    if not terms:
        raise ValueError("folder query contained no valid search terms")
    return ", ".join(terms)


def _normalize_wazuh_query(value: str) -> str:
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
        raise ValueError("query was not valid JSON")
    if not isinstance(payload, dict):
        raise ValueError("query payload was not an object")
    clause = payload.get("query", payload)
    if not isinstance(clause, dict):
        raise ValueError("query clause was not an object")
    # The connector is authoritative. Reject common unsafe or unsupported
    # model constructs; the caller retries and ultimately fails closed.
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
        raise ValueError("query used a disallowed or ungrounded query construct")
    return json.dumps({"query": clause}, separators=(",", ":"), ensure_ascii=False)


def validate_and_normalize_query(value: str, hypothesis_text: str,
                                 siem_type: str) -> dict:
    """Deterministically validate a model query without inventing a fallback.

    This function performs no model call. It is used both after query
    generation and immediately before execution, so reasoning-generated
    follow-up queries cannot bypass the syntax/read-only checks.
    """
    dialect = (siem_type or "folder").lower()
    candidate = (value or "").strip()
    error = None
    try:
        if not candidate:
            raise ValueError("query generator returned an empty query")
        if dialect in FOLDER_SIEM_TYPES:
            normalized = _normalize_folder_query(candidate)
        elif dialect in {"wazuh", "elasticsearch"}:
            normalized = _normalize_wazuh_query(candidate)
        elif dialect in {"splunk", "qradar", "logrhythm"}:
            normalized = _validate_text_query(candidate, dialect)
        else:
            normalized = _validate_text_query(candidate, dialect)
    except ValueError as exc:
        error = str(exc)
        normalized = ""
    return {
        "query": normalized,
        "used_fallback": error is not None,
        "validation_error": error,
    }


async def generate_query(
    hypothesis_text: str,
    siem_type: str = "folder",
    objective: str = "Retrieve direct evidence that supports or refutes the hypothesis.",
    investigation_context: dict | None = None,
) -> dict:
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
    # Version query-generation behavior so cached output is invalidated when
    # validation or prompt contracts change.
    cache_version = "v10"
    field_signature = json.dumps(field_map, sort_keys=True, separators=(",", ":"))
    query_model = target_for("query_gen").model
    bounded_context = json.dumps(
        investigation_context or {},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )[:8_000]
    cache_payload = (
        f"{cache_version}|{query_model}|{siem_type}|{field_signature}|"
        f"{objective}|{bounded_context}|{hypothesis_text}"
    )
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

    validation = None
    failures: list[str] = []
    if siem_type.lower() in FOLDER_SIEM_TYPES:
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Investigation step objective: {objective}\n"
            f"Prior retrieval context: {bounded_context}\n\n"
            f"Normalized fields available: {field_map}\n\n"
            f"Generate the keyword list now."
        )
        system_prompt = FOLDER_SYSTEM_PROMPT
    elif siem_type.lower() in {"wazuh", "elasticsearch"}:
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Investigation step objective: {objective}\n"
            f"Prior retrieval context: {bounded_context}\n\n"
            f"{siem_type.title()} field mapping: {field_map}\n\n"
            "Generate the JSON Query DSL now."
        )
        system_prompt = WAZUH_SYSTEM_PROMPT
    else:
        prompt = (
            f"Hypothesis: {hypothesis_text}\n\n"
            f"Investigation step objective: {objective}\n"
            f"Prior retrieval context: {bounded_context}\n\n"
            f"Target SIEM: {siem_type}\n"
            f"Field mapping: {field_map}\n\n"
            f"Generate the query now."
        )
        system_prompt = SYSTEM_PROMPT

    query_text = ""
    configured_attempts = int(
        get_value("autonomy", "query_generation_attempts", default=3)
    )
    for attempt in range(1, max(1, min(configured_attempts, 10)) + 1):
        attempt_prompt = prompt
        if failures:
            attempt_prompt += (
                "\n\nThe previous response failed deterministic source and "
                f"read-only validation: {failures[-1]}. Rebuild the query from "
                "the supplied schema and objective. Do not return an availability "
                "query, example query, explanation, or invented field."
            )
        try:
            candidate = await ollama_generate(
                prompt=attempt_prompt,
                system=system_prompt,
                agent="query_gen",
            )
        except Exception as exc:
            failures.append(str(exc) or exc.__class__.__name__)
            continue
        candidate_validation = validate_and_normalize_query(
            candidate, hypothesis_text, siem_type
        )
        if not candidate_validation["used_fallback"]:
            query_text = candidate_validation["query"]
            validation = candidate_validation
            break
        failures.append(
            candidate_validation["validation_error"]
            or "query did not pass source safety/schema validation"
        )

    if validation is None:
        validation = {
            "query": "",
            "used_fallback": True,
            "validation_error": (
                "; ".join(failures)
                or "query generation failed without a validated response"
            ),
        }
    query_text = validation["query"]
    # Cache only a model-generated query that passed validation. A degraded
    # availability search must not become the permanent answer for later hunts.
    if not validation["used_fallback"]:
        await asyncio.to_thread(cache.cache_set, "query_gen", cache_payload, query_text)

    return {
        "siem_type": siem_type,
        "hypothesis": hypothesis_text,
        "query": query_text,
        "query_used_fallback": validation["used_fallback"],
        "query_validation_error": validation["validation_error"],
    }
