"""
Query generator tool — turns a hunting hypothesis into a concrete SIEM
query, grounded in the SIEM-KB field mapping so the LLM doesn't
hallucinate field names.
"""
import asyncio
import ipaddress
import json
import re
from typing import Iterable

from services.siem.clients import ollama_generate
from services.siem.siem_kb import (
    get_field_capabilities,
    get_field_mapping,
    get_field_query_priorities,
    get_field_value_kinds,
)
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
    "You are a senior SOC threat hunter selecting a bounded read-only "
    "OpenSearch/Elasticsearch query plan for the supplied investigation step "
    "and security-event field catalog. Return only the schema-constrained "
    "object. Select at least one clause for every supplied evidence branch. "
    "Select exact branch/field/value combinations only from the supplied "
    "enums; "
    "never invent example PIDs, users, states, addresses, ports, process "
    "names, or other values. Cover every "
    "distinct evidence branch stated by the hypothesis that is representable "
    "in the supplied source schema. Use match_phrase for text and term for "
    "exact scalar, identifier, port, protocol, or boolean values. Prefer "
    "high-specificity literal observables over generic prose. THOS compiles "
    "the selected clauses and adds the time range, target indices, and result "
    "cap separately."
)

def _query_field_catalog(
    field_map: dict,
    field_capabilities: dict[str, list[str]] | None = None,
    field_value_kinds: dict[str, list[str]] | None = None,
    field_query_priorities: dict[str, int] | None = None,
) -> dict:
    """Expand data-configured field alternatives into exact field names."""
    inventory = {
        item.strip()
        for item in str(field_map.get("available_fields") or "").split(",")
        if item.strip()
    }
    groups: dict[str, list[str]] = {}
    field_data_sources: dict[str, list[str]] = {}
    exact_field_value_kinds: dict[str, list[str]] = {}
    exact_field_priorities: dict[str, int] = {}
    allowed: list[str] = []
    for normalized_name, configured in field_map.items():
        if normalized_name == "available_fields":
            continue
        text = str(configured or "").strip()
        if not text:
            continue
        fields = [
            item.strip()
            for item in text.split(" / ")
            if item.strip() and "*" not in item and len(item.strip()) <= 200
        ]
        if inventory:
            fields = [field for field in fields if field in inventory]
        if fields:
            groups[str(normalized_name)] = list(dict.fromkeys(fields))
            allowed.extend(fields)
            capabilities = (
                field_capabilities or {}
            ).get(str(normalized_name), [])
            for field in fields:
                field_data_sources[field] = list(dict.fromkeys(
                    str(capability)
                    for capability in capabilities
                    if str(capability).strip()
                ))
                exact_field_value_kinds[field] = list(dict.fromkeys(
                    str(kind)
                    for kind in (
                        field_value_kinds or {}
                    ).get(str(normalized_name), [])
                    if str(kind).strip()
                ))
                exact_field_priorities[field] = int(
                    (field_query_priorities or {}).get(
                        str(normalized_name),
                        50,
                    )
                )
    return {
        "normalized_fields": groups,
        "allowed_fields": list(dict.fromkeys(allowed)),
        "field_data_sources": field_data_sources,
        "field_value_kinds": exact_field_value_kinds,
        "field_query_priorities": exact_field_priorities,
    }


def _grounded_query_literals(
    hypothesis_text: str,
    objective: str,
    investigation_context: dict | None,
) -> list[str]:
    """Build model choices only from governed input text and scalar context."""
    values: list[str] = []

    def add(value):
        text = str(value or "").strip()
        if (
            1 < len(text) <= 200
            and not re.fullmatch(r"(?:[A-Za-z]\.)+[A-Za-z]?", text)
        ):
            values.append(text)

    scalar_keys = {
        "technique_id",
        "technique_name",
        "tactic",
    }
    container_keys = {
        "literal_observables",
        "technique",
        "observed_entities",
        "governed_indicators",
        "event_ids",
        "keywords",
        "behavior_phrases",
    }

    def walk(value, include_scalars: bool = False):
        if isinstance(value, dict):
            for key, child in value.items():
                key_name = str(key)
                if key_name in scalar_keys:
                    add(child)
                elif key_name in container_keys:
                    walk(child, include_scalars=True)
                elif include_scalars:
                    walk(child, include_scalars=True)
                else:
                    walk(child, include_scalars=False)
        elif isinstance(value, (list, tuple, set)):
            for child in value:
                walk(child, include_scalars=include_scalars)
        elif include_scalars and isinstance(value, (str, int, float)):
            add(value)

    walk(investigation_context or {})
    # The supervisor objective also contains execution controls such as
    # lookback days and result limits. Those numbers guide retrieval but are
    # not evidence observables and must never become query values. Observable
    # literals come from the hypothesis and explicitly governed context.
    combined = hypothesis_text
    for token in re.findall(
        r"\b(?:[A-Za-z][A-Za-z0-9_.:/-]{2,}|[0-9]{2,})\b",
        combined,
    ):
        if (
            any(character.isdigit() for character in token)
            or any(character in "._:/-" for character in token)
            or token.isupper()
            or any(character.isupper() for character in token[1:])
        ):
            add(token)
    for value in list(values):
        match = re.fullmatch(r"(.+)\.([A-Za-z0-9]{2,8})", value)
        if match and len(match.group(1)) > 1:
            add(match.group(1))
        if "/" in value:
            for component in value.split("/"):
                if component.isdigit():
                    add(component)
    return _unique_casefold(values)[:256]


def _unique_casefold(values: Iterable[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        marker = text.casefold()
        if text and marker not in seen:
            seen.add(marker)
            unique.append(text)
    return unique


def _wazuh_plan_schema(
    allowed_fields: list[str],
    grounded_literals: list[str],
    branch_fields: dict[str, list[str]] | None = None,
) -> dict:
    if not allowed_fields:
        raise ValueError(
            "source field catalog has no governed fields present in inventory"
        )
    if not grounded_literals:
        raise ValueError("hypothesis supplied no grounded query literals")
    clause_properties = {
        "field": {
            "type": "string",
            "enum": allowed_fields,
        },
        "operator": {
            "type": "string",
            "enum": ["match_phrase", "term"],
        },
        "value": {
            "type": "string",
            "enum": grounded_literals,
        },
    }
    clause_required = ["field", "operator", "value"]
    clause_schema = {
        "type": "object",
        "properties": clause_properties,
        "required": clause_required,
        "additionalProperties": False,
    }
    if branch_fields:
        branch_schemas = {
            branch: {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "items": {
                    **clause_schema,
                    "properties": {
                        **clause_schema["properties"],
                        "field": {
                            "type": "string",
                            "enum": fields,
                        },
                    },
                },
            }
            for branch, fields in branch_fields.items()
        }
        return {
            "type": "object",
            "properties": {
                "branches": {
                    "type": "object",
                    "properties": branch_schemas,
                    "required": list(branch_schemas),
                    "additionalProperties": False,
                },
            },
            "required": ["branches"],
            "additionalProperties": False,
        }
    return {
        "type": "object",
        "properties": {
            "clauses": {
                "type": "array",
                "minItems": 1,
                "maxItems": 12,
                "items": clause_schema,
            },
        },
        "required": ["clauses"],
        "additionalProperties": False,
    }


def _compile_wazuh_plan(
    value: str,
    allowed_fields: list[str],
    grounded_literals: list[str],
    branch_fields: dict[str, list[str]] | None = None,
    field_value_kinds: dict[str, list[str]] | None = None,
) -> str:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("query plan was not valid JSON") from exc
    clauses = []
    if branch_fields:
        branches = (
            payload.get("branches")
            if isinstance(payload, dict)
            else None
        )
        if not isinstance(branches, dict):
            raise ValueError("query plan contained no evidence branches")
        for branch in branch_fields:
            branch_clauses = branches.get(branch)
            if not isinstance(branch_clauses, list) or not branch_clauses:
                raise ValueError(
                    f"query plan omitted required evidence branch: {branch}"
                )
            clauses.extend({
                **clause,
                "_branch": branch,
            } for clause in branch_clauses if isinstance(clause, dict))
    else:
        supplied = payload.get("clauses") if isinstance(payload, dict) else None
        if isinstance(supplied, list):
            clauses = supplied
    if not clauses:
        raise ValueError("query plan contained no clauses")
    fields = set(allowed_fields)
    literals = {literal.casefold() for literal in grounded_literals}
    literal_kinds = _literal_kinds(grounded_literals)
    compiled = []
    seen = set()
    seen_branches: set[str] = set()
    for clause in clauses[:12]:
        if not isinstance(clause, dict):
            raise ValueError("query plan clause was not an object")
        field = str(clause.get("field") or "")
        operator = str(clause.get("operator") or "")
        literal = str(clause.get("value") or "")
        branch = str(clause.get("_branch") or "")
        if field not in fields:
            raise ValueError(f"query plan selected an unavailable field: {field}")
        if branch_fields:
            if branch not in branch_fields:
                raise ValueError(
                    f"query plan selected an unavailable branch: {branch}"
                )
            if field not in set(branch_fields[branch]):
                raise ValueError(
                    f"query plan field {field} cannot represent branch {branch}"
                )
            seen_branches.add(branch)
        if operator not in {"match_phrase", "term"}:
            raise ValueError(
                f"query plan selected an unsupported operator: {operator}"
            )
        if literal.casefold() not in literals:
            raise ValueError(
                f"query plan selected an ungrounded value: {literal}"
            )
        if field_value_kinds is not None:
            accepted_kinds = set(field_value_kinds.get(field) or [])
            actual_kinds = literal_kinds.get(literal.casefold(), set())
            if not accepted_kinds & actual_kinds:
                raise ValueError(
                    f"query plan value {literal} is incompatible with "
                    f"field {field}"
                )
        marker = (field, operator, literal.casefold())
        if marker not in seen:
            seen.add(marker)
            compiled.append({operator: {field: literal}})
    if branch_fields:
        missing_branches = [
            branch for branch in branch_fields if branch not in seen_branches
        ]
        if missing_branches:
            raise ValueError(
                "query plan omitted required evidence branches: "
                + ", ".join(missing_branches)
            )
    if not compiled:
        raise ValueError("query plan contained no unique clauses")
    query = (
        compiled[0]
        if len(compiled) == 1
        else {
            "bool": {
                "should": compiled,
                "minimum_should_match": 1,
            },
        }
    )
    return json.dumps(
        {"query": query},
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _literal_kinds(
    literals: list[str],
) -> dict[str, set[str]]:
    artifacts = {
        literal.casefold()
        for literal in literals
        if re.fullmatch(r".+\.[A-Za-z0-9]{2,8}", literal)
    }
    artifact_stems = {
        artifact.rsplit(".", 1)[0]
        for artifact in artifacts
    }
    output: dict[str, set[str]] = {}
    for literal in literals:
        lowered = literal.casefold()
        kinds: set[str] = set()
        if lowered in artifacts or lowered in artifact_stems:
            kinds.add("artifact")
        if re.fullmatch(r"\d+", literal):
            kinds.update({"integer", "identifier"})
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", literal, re.IGNORECASE):
            kinds.update({"technique", "identifier"})
        if literal in {"true", "false"}:
            kinds.add("boolean")
        try:
            ipaddress.ip_address(literal)
            kinds.update({"ip", "entity"})
        except ValueError:
            pass
        if (
            re.fullmatch(r"[A-Z][A-Z0-9-]{1,11}", literal)
            and not any(character.isdigit() for character in literal)
        ):
            kinds.add("protocol")
        if " " in literal:
            kinds.add("phrase")
        if (
            "." in literal
            and "artifact" not in kinds
            and not literal.startswith(".")
        ):
            kinds.update({"domain", "entity"})
        output[lowered] = kinds
    return output


def _compile_grounded_branch_query(
    branch_fields: dict[str, list[str]],
    field_value_kinds: dict[str, list[str]],
    grounded_literals: list[str],
    field_query_priorities: dict[str, int] | None = None,
) -> str:
    """Compile capability-complete clauses from governed catalogs and values."""
    value_kinds = _literal_kinds(grounded_literals)
    compiled = []
    for branch, fields in branch_fields.items():
        field_clauses: list[tuple[int, list[dict]]] = []
        for field in fields:
            accepted = set(field_value_kinds.get(field) or [])
            if not accepted:
                continue
            matches = [
                literal
                for literal in grounded_literals
                if accepted & value_kinds.get(literal.casefold(), set())
            ][:8]
            clauses = []
            for literal in matches:
                kinds = value_kinds.get(literal.casefold(), set())
                operator = (
                    "term"
                    if kinds & {
                        "boolean", "integer", "protocol",
                        "identifier", "ip", "domain",
                    }
                    else "match_phrase"
                )
                clauses.append({
                    operator: {field: literal},
                })
            if clauses:
                field_clauses.append((
                    int((field_query_priorities or {}).get(field, 50)),
                    clauses,
                ))
        if not field_clauses:
            raise ValueError(
                f"no grounded field/value pair can represent branch {branch}"
            )
        highest_priority = max(priority for priority, _ in field_clauses)
        for priority, clauses in field_clauses:
            if priority >= highest_priority - 10:
                compiled.extend(clauses)
    if not compiled:
        raise ValueError("governed query compiler produced no clauses")
    return json.dumps({
        "query": {
            "bool": {
                "should": compiled[:120],
                "minimum_should_match": 1,
            },
        },
    }, separators=(",", ":"), ensure_ascii=False)


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


def _normalize_wazuh_query(
    value: str,
    allowed_fields: list[str] | None = None,
    grounding_text: str | None = None,
) -> str:
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
    if not clause:
        raise ValueError("query clause was empty")
    # Time bounds are connector-owned. Small local models sometimes repeat a
    # duration from the objective even after being told not to. Remove only
    # those control clauses while preserving every model-selected evidence
    # clause; a range-only response still fails closed below.
    removed = object()

    def strip_connector_controls(item):
        if isinstance(item, dict):
            if not item:
                return {}
            cleaned = {}
            removed_child = False
            for key, child in item.items():
                if str(key).lower() == "range":
                    removed_child = True
                    continue
                value = strip_connector_controls(child)
                if value is removed:
                    removed_child = True
                    continue
                cleaned[key] = value
            if "bool" in cleaned and isinstance(cleaned["bool"], dict):
                if "should" not in cleaned["bool"]:
                    cleaned["bool"].pop("minimum_should_match", None)
            return cleaned if cleaned or not removed_child else removed
        if isinstance(item, list):
            cleaned = [
                value
                for child in item
                if (value := strip_connector_controls(child)) is not removed
            ]
            return cleaned if cleaned else removed
        return item

    sanitized_clause = strip_connector_controls(clause)
    if sanitized_clause is removed or not isinstance(sanitized_clause, dict) \
            or not sanitized_clause:
        raise ValueError(
            "query contained only a model-supplied range; THOS owns the "
            "bounded time window and requires an evidence clause"
        )
    clause = sanitized_clause
    # The connector is authoritative. Reject common unsafe or unsupported
    # model constructs; the caller retries and ultimately fails closed.
    def first_disallowed(item):
        if isinstance(item, dict):
            for key, child in item.items():
                lowered = str(key).lower()
                if lowered == "query_string":
                    return (
                        "query_string is forbidden; use match_phrase, term, "
                        "terms, exists, or simple_query_string with exact "
                        "allowed_fields"
                    )
                if str(key).lower() in {"simple_query_string", "multi_match"} \
                        and isinstance(child, dict):
                    fields = child.get("fields", [])
                    if not isinstance(fields, list) or any(
                        not isinstance(field, str) or "*" in field
                        for field in fields
                        ):
                            return (
                                f"{lowered} contains a disallowed wildcard or "
                                "does not contain an explicit fields list"
                            )
                nested = first_disallowed(child)
                if nested:
                    return nested
        elif isinstance(item, list):
            for child in item:
                nested = first_disallowed(child)
                if nested:
                    return nested
        return ""

    disallowed = first_disallowed(clause)
    if disallowed:
        raise ValueError(disallowed)

    if allowed_fields is not None:
        referenced: list[str] = []

        def collect_fields(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    lowered = str(key).lower()
                    if lowered in {
                        "match", "match_phrase", "term", "terms",
                    } and isinstance(child, dict):
                        referenced.extend(str(field) for field in child)
                    elif lowered == "exists" and isinstance(child, dict):
                        field = child.get("field")
                        if field:
                            referenced.append(str(field))
                    elif lowered in {"simple_query_string", "multi_match"} \
                            and isinstance(child, dict):
                        fields = child.get("fields")
                        if isinstance(fields, list):
                            referenced.extend(str(field) for field in fields)
                    collect_fields(child)
            elif isinstance(item, list):
                for child in item:
                    collect_fields(child)

        collect_fields(clause)
        permitted = {field.split("^", 1)[0] for field in allowed_fields}
        unknown = sorted({
            field.split("^", 1)[0]
            for field in referenced
            if field.split("^", 1)[0] not in permitted
        })
        if unknown:
            raise ValueError(
                "query referenced fields outside allowed_fields: "
                + ", ".join(unknown[:20])
            )

    if grounding_text is not None:
        evidence_values: list[str] = []

        def collect_values(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    lowered = str(key).lower()
                    if lowered in {
                        "match", "match_phrase", "term", "terms",
                    } and isinstance(child, dict):
                        for value in child.values():
                            if isinstance(value, dict):
                                value = value.get("query")
                            values = value if isinstance(value, list) else [value]
                            evidence_values.extend(
                                str(candidate).strip()
                                for candidate in values
                                if candidate not in (None, "")
                            )
                    elif lowered in {
                        "simple_query_string", "multi_match",
                    } and isinstance(child, dict):
                        query_value = child.get("query")
                        if query_value not in (None, ""):
                            evidence_values.append(str(query_value).strip())
                    collect_values(child)
            elif isinstance(item, list):
                for child in item:
                    collect_values(child)

        collect_values(clause)
        grounded = grounding_text.casefold()
        ungrounded: list[str] = []
        query_operators = {"and", "or", "not", "true", "false"}
        for value in evidence_values:
            normalized_value = value.casefold()
            if (
                normalized_value in query_operators
                or normalized_value in grounded
            ):
                continue
            tokens = [
                token.casefold()
                for token in re.findall(r"[A-Za-z0-9_.:/-]+", value)
                if token.casefold() not in query_operators
            ]
            if not tokens or any(token not in grounded for token in tokens):
                ungrounded.append(value)
        if ungrounded:
            raise ValueError(
                "query invented values outside the supplied hypothesis, "
                "objective, and governed context: "
                + ", ".join(list(dict.fromkeys(ungrounded))[:20])
            )
    return json.dumps({"query": clause}, separators=(",", ":"), ensure_ascii=False)


def validate_and_normalize_query(
    value: str,
    hypothesis_text: str,
    siem_type: str,
    *,
    allowed_fields: list[str] | None = None,
    grounding_text: str | None = None,
) -> dict:
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
            normalized = _normalize_wazuh_query(
                candidate,
                allowed_fields=allowed_fields,
                grounding_text=grounding_text,
            )
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
    cache_version = "v19"
    field_signature = json.dumps(field_map, sort_keys=True, separators=(",", ":"))
    query_field_catalog = _query_field_catalog(
        field_map,
        get_field_capabilities(),
        get_field_value_kinds(),
        get_field_query_priorities(),
    )
    grounded_literals = _grounded_query_literals(
        hypothesis_text,
        objective,
        investigation_context,
    )
    required_data_sources: list[str] = []

    def collect_required_sources(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key) == "required_data_sources" \
                        and isinstance(child, list):
                    required_data_sources.extend(
                        str(source)
                        for source in child
                        if str(source).strip()
                    )
                else:
                    collect_required_sources(child)
        elif isinstance(value, list):
            for child in value:
                collect_required_sources(child)

    collect_required_sources(investigation_context or {})
    required_data_sources = list(dict.fromkeys(required_data_sources))
    branch_fields = {
        source: [
            field
            for field, capabilities in (
                query_field_catalog["field_data_sources"]
            ).items()
            if source in capabilities
        ]
        for source in required_data_sources
    }
    branch_fields = {
        source: fields
        for source, fields in branch_fields.items()
        if fields
    }
    governed_query = ""
    governed_query_error = ""
    if branch_fields and siem_type.lower() in {"wazuh", "elasticsearch"}:
        try:
            governed_query = _compile_grounded_branch_query(
                branch_fields,
                query_field_catalog["field_value_kinds"],
                grounded_literals,
                query_field_catalog["field_query_priorities"],
            )
        except ValueError as exc:
            governed_query_error = str(exc)
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
    grounding_text = "\n".join([
        hypothesis_text,
        objective,
        bounded_context,
    ])
    cached_query = await asyncio.to_thread(cache.cache_get, "query_gen", cache_payload)
    if isinstance(cached_query, str) and cached_query.strip():
        cached_validation = validate_and_normalize_query(
            cached_query,
            hypothesis_text,
            siem_type,
            allowed_fields=query_field_catalog["allowed_fields"],
            grounding_text=grounding_text,
        )
        if not cached_validation["used_fallback"]:
            return {
                "siem_type": siem_type,
                "hypothesis": hypothesis_text,
                "query": cached_validation["query"],
                "query_used_fallback": False,
                "query_validation_error": None,
                "query_generation_mode": "cache",
                "query_generation_warnings": [],
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
            f"{siem_type.title()} field catalog: "
            f"{json.dumps(query_field_catalog, separators=(',', ':'))}\n\n"
            "Grounded literal choices: "
            f"{json.dumps(grounded_literals, separators=(',', ':'))}\n\n"
            "Required evidence branches and eligible fields: "
            f"{json.dumps(branch_fields, separators=(',', ':'))}\n\n"
            "Select the schema-constrained query plan now."
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
    query_generation_mode = "model"
    configured_attempts = int(
        get_value("autonomy", "query_generation_attempts", default=3)
    )
    if governed_query:
        governed_validation = validate_and_normalize_query(
            governed_query,
            hypothesis_text,
            siem_type,
            allowed_fields=query_field_catalog["allowed_fields"],
            grounding_text=grounding_text,
        )
        if not governed_validation["used_fallback"]:
            validation = governed_validation
            query_text = governed_validation["query"]
            query_generation_mode = "governed_compiler"
        else:
            failures.append(
                governed_validation["validation_error"]
                or "governed query did not pass source safety/schema validation"
            )
    attempt_budget = (
        0
        if validation is not None
        else max(1, min(configured_attempts, 10))
    )
    for attempt in range(1, attempt_budget + 1):
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
                format=(
                    _wazuh_plan_schema(
                        query_field_catalog["allowed_fields"],
                        grounded_literals,
                        branch_fields,
                    )
                    if siem_type.lower() in {"wazuh", "elasticsearch"}
                    else None
                ),
            )
            if siem_type.lower() in {"wazuh", "elasticsearch"}:
                candidate = _compile_wazuh_plan(
                    candidate,
                    query_field_catalog["allowed_fields"],
                    grounded_literals,
                    branch_fields,
                    query_field_catalog["field_value_kinds"],
                )
        except Exception as exc:
            failures.append(str(exc) or exc.__class__.__name__)
            continue
        candidate_validation = validate_and_normalize_query(
            candidate,
            hypothesis_text,
            siem_type,
            allowed_fields=query_field_catalog["allowed_fields"],
            grounding_text=grounding_text,
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
        if governed_query_error:
            failures.append(governed_query_error)
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
        "query_generation_mode": query_generation_mode,
        "query_generation_warnings": failures,
    }
