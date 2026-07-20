"""
THOS MCP Server — registers every SOC tool over the MCP protocol so
the LangGraph orchestrator (or any other MCP-compatible client) can
call them uniformly.

Adding a new tool in later phases:
  1. Write the implementation in app/tools/<your_tool>.py
  2. Import it below
  3. Wrap it with @mcp.tool() following the pattern of the existing tools
That's it — no changes needed anywhere else. The orchestrator discovers
tools dynamically via MCP's list_tools.
"""
import logging
import os
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from services.hunting import hearth
from services.knowledge import mitre
from services.detection import detection_rules
from services.siem import siem_kb, siem_connector
from services.observability import cache
from services.reporting import report
from services.hunting.query_generator import generate_query
from services.observability.logging_config import configure_logging

# As early as possible: same structured-JSON-to-stdout setup used by the
# orchestrator (see services/observability/logging_config.py), so tool
# call errors/warnings in this process are aggregator-ready too instead
# of plain print() text.
configure_logging("thos-mcp")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# Auth
# ---------------------------------------------------------------
# This MCP server can run SIEM queries, read/write every hunt report, and
# call every SOC tool — it must never be reachable without credentials.
# The orchestrator is the only intended caller; it authenticates with the
# same shared bearer token via MCP_AUTH_TOKEN (see services/mcp/mcp_client.py).
# A weak "_change_me" default is provided so `docker compose up` still works
# out of the box, matching this repo's existing POSTGRES_PASSWORD pattern —
# but it must be overridden with a real secret (e.g. `openssl rand -hex 32`)
# before this ever runs on a network anyone else can reach.
_DEFAULT_MCP_AUTH_TOKEN = "thos_change_me_mcp_token"
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", _DEFAULT_MCP_AUTH_TOKEN)
if MCP_AUTH_TOKEN == _DEFAULT_MCP_AUTH_TOKEN:
    logger.warning(
        "MCP_AUTH_TOKEN is unset, using the built-in default. Set "
        "MCP_AUTH_TOKEN to a real secret (and mirror it in the "
        "orchestrator's MCP_AUTH_TOKEN) before exposing this service "
        "beyond a trusted local dev network."
    )

mcp = FastMCP(
    "THOS-SOC-Tools",
    auth=StaticTokenVerifier(
        tokens={
            MCP_AUTH_TOKEN: {
                "client_id": "thos-orchestrator",
                "scopes": ["tools:call"],
            }
        }
    ),
)


# ---------------------------------------------------------------
# Hypothesis tools (HEARTH)
# ---------------------------------------------------------------
@mcp.tool()
def list_hearth_hypotheses(tactic: str = "") -> list[dict]:
    """List available HEARTH-style threat hunting hypotheses, optionally filtered by MITRE ATT&CK tactic name."""
    return hearth.list_hypotheses(tactic or None)


@mcp.tool()
def get_hearth_hypothesis(hypothesis_id: str) -> dict:
    """Get full detail for a single hypothesis by its ID (e.g. H-001)."""
    result = hearth.get_hypothesis(hypothesis_id)
    return result or {"error": f"hypothesis {hypothesis_id} not found"}


@mcp.tool()
def search_hypotheses_semantic(query: str, n_results: int = 3) -> list[dict]:
    """Semantic RAG search over the ingested HEARTH knowledge base for hypotheses matching free-text intent."""
    return hearth.semantic_search_hypotheses(query, n_results)


@mcp.tool()
def refresh_hearth_hypotheses() -> dict:
    """Fetch the latest HEARTH hypotheses live from
    https://github.com/THORCollective/HEARTH and re-ingest them into the
    hearth_kb vector store, so list_hearth_hypotheses / semantic search
    reflect whatever's newest upstream. Falls back gracefully (returns an
    error field, doesn't raise) if there's no route to github.com — e.g.
    a fully air-gapped on-prem deployment."""
    from services.knowledge.hearth_fetch import fetch_and_parse_hearth
    from services.siem.clients import get_or_create_collection

    try:
        items = fetch_and_parse_hearth()
    except Exception as e:  # noqa: BLE001
        return {"refreshed": False, "count": 0, "error": str(e)}

    collection = get_or_create_collection("hearth_kb")
    ids = [h["id"] for h in items]
    docs = [f'{h["title"]}. {h["text"]}' for h in items]
    metas = [
        {
            "id": h["id"], "title": h["title"], "tactic": h.get("tactic", ""),
            "technique": h.get("technique", ""), "text": h["text"],
        }
        for h in items
    ]
    if ids:
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
    return {"refreshed": True, "count": len(ids)}


# ---------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------
@mcp.tool()
def mitre_map_technique(technique_id: str) -> dict:
    """Map a MITRE ATT&CK technique ID (e.g. T1059.001) to its name, tactic, description and typical data sources."""
    result = mitre.map_technique(technique_id)
    return result or {"error": f"technique {technique_id} not in local table"}


# ---------------------------------------------------------------
# Detection rule generation
# ---------------------------------------------------------------
@mcp.tool()
def generate_sigma_rule(title: str, log_category: str, selection_field: str,
                         selection_value: str, level: str = "medium") -> str:
    """Generate a draft SIGMA detection rule skeleton for a given log category and selection criteria."""
    return detection_rules.generate_sigma_skeleton(title, log_category, selection_field, selection_value, level)


@mcp.tool()
def generate_yara_rule(rule_name: str, strings: dict, condition: str = "any of them") -> str:
    """Generate a draft YARA rule skeleton from a dict of string identifiers to string values."""
    return detection_rules.generate_yara_skeleton(rule_name, strings, condition)


@mcp.tool()
async def derive_detection_indicators(hypothesis_text: str, technique_id: str = "",
                                       technique_name: str = "", tactic: str = "") -> dict:
    """LLM-derive candidate detection indicators (relevant Event IDs +
    keyword substrings) for a hunting hypothesis + MITRE ATT&CK context.
    Grounded in the LLM's security knowledge for THIS specific hunt,
    rather than a static hardcoded technique-id -> indicator table."""
    from services.detection.indicator_deriver import derive_indicators
    return await derive_indicators(hypothesis_text, technique_id, technique_name, tactic)


# ---------------------------------------------------------------
# SIEM-KB (field mappings / schema info)
# ---------------------------------------------------------------
@mcp.tool()
def siem_field_mapping(siem_type: str) -> dict:
    """Return normalized-to-vendor field mappings for a supported SIEM."""
    return siem_kb.get_field_mapping(siem_type)


# ---------------------------------------------------------------
# Query generation (LLM-assisted, grounded in SIEM-KB)
# ---------------------------------------------------------------
@mcp.tool()
async def generate_siem_query(hypothesis_text: str, siem_type: str = "mock") -> dict:
    """Generate a concrete SIEM query for the given hypothesis text and target SIEM type."""
    return await generate_query(hypothesis_text, siem_type)


# ---------------------------------------------------------------
# SIEM connector (log fetch)
# ---------------------------------------------------------------
@mcp.tool()
def fetch_siem_logs(query: str, limit: int = 25, siem_type: str = "",
                     log_source_path: str = "") -> dict:
    """Execute a SIEM query and fetch matching log records. In 'mock' mode
    returns synthetic records. In 'wazuh' mode, searches the Wazuh
    Indexer. In 'folder' mode, parses every supported
    log file (evtx/log/syslog/csv/CEF/JSON/ECS/xml/txt/pcap) under
    log_source_path and returns records matching the query."""
    return siem_connector.fetch_logs(query, limit, siem_type=siem_type or None,
                                      log_source_path=log_source_path)


@mcp.tool()
def list_log_source_files(folder: str) -> dict:
    """List every supported log file (evtx/log/syslog/csv/CEF/JSON/ECS/xml/txt/pcap)
    found under a local folder, without parsing them — useful for the UI to show
    what's available before running a hunt against it."""
    from services.siem import file_log_parser
    try:
        file_log_parser.validate_log_source_path(folder)
    except file_log_parser.LogSourcePathError as e:
        return {"folder": folder, "count": 0, "files": [], "error": str(e)}
    files = file_log_parser.list_supported_files(folder)
    return {"folder": folder, "count": len(files), "files": [os.path.basename(f) for f in files]}


# ---------------------------------------------------------------
# Custom Knowledge Base (analyst-uploaded documents — AnythingLLM-style)
# ---------------------------------------------------------------
@mcp.tool()
def upload_kb_document(filename: str, content_b64: str) -> dict:
    """Ingest an uploaded document (base64-encoded bytes) into the custom
    knowledge base: extracts its text, splits it into overlapping chunks,
    and embeds them into the 'custom_kb' Chroma collection for semantic
    search. Supported types: txt, md, csv, tsv, json, log, html/htm,
    pdf, docx. Returns {"error": ...} instead of raising for any
    user-facing problem (unsupported type, empty file, too large)."""
    import base64
    from services.knowledge import custom_kb
    try:
        content = base64.b64decode(content_b64)
    except Exception as e:  # noqa: BLE001
        return {"error": f"invalid base64 content: {e}"}
    try:
        return custom_kb.ingest_document(filename, content)
    except custom_kb.KnowledgeBaseError as e:
        return {"error": str(e)}


@mcp.tool()
def list_kb_documents() -> list[dict]:
    """List every document currently ingested into the custom knowledge base."""
    from services.knowledge import custom_kb
    return custom_kb.list_documents()


@mcp.tool()
def delete_kb_document(doc_id: str) -> dict:
    """Remove a document (all of its chunks) from the custom knowledge base by doc_id."""
    from services.knowledge import custom_kb
    return custom_kb.delete_document(doc_id)


@mcp.tool()
def search_knowledge_base(query: str, n_results: int = 5) -> list[dict]:
    """Semantic search over analyst-uploaded documents in the custom
    knowledge base (playbooks, threat intel, IR runbooks, past hunt
    write-ups, vendor advisories, etc.) — separate from the built-in
    hearth_kb/mitre_kb/siem_kb collections."""
    from services.knowledge import custom_kb
    return custom_kb.search(query, n_results)


# ---------------------------------------------------------------
# Cache / rate limiting
# ---------------------------------------------------------------
@mcp.tool()
def cache_lookup(namespace: str, payload: str) -> dict:
    """Look up a cached result for a given namespace + payload combination."""
    result = cache.cache_get(namespace, payload)
    return {"hit": result is not None, "value": result}


@mcp.tool()
def cache_store(namespace: str, payload: str, value: dict, ttl_seconds: int = 900) -> dict:
    """Store a value in cache under namespace + payload, with a TTL."""
    cache.cache_set(namespace, payload, value, ttl_seconds)
    return {"stored": True}


# ---------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------
@mcp.tool()
def write_hunt_report(hunt_id: str, title: str, hypothesis: str, technique_id: str,
                       technique_name: str, tactic: str, summary: str, queries: str,
                       findings: str, recommendations: str, log_sample: str,
                       hypothesis_id: str = "", log_source: str = "",
                       ingestion_diagnostics: str = "", hunter_name: str = "",
                       cover_style: str = "1", sigma_matched_count: int = 0,
                       records_analyzed: int = 0) -> dict:
    """Write the final markdown threat hunt report to the shared reports
    volume. `title` may be left empty — the report will auto-derive a
    short title from technique/tactic/hypothesis_id rather than using
    the full hypothesis text. `cover_style`: "1" = executive cover page,
    "2" = SOC analyst cover panel."""
    path = report.write_report(
        hunt_id, title, hypothesis, technique_id, technique_name, tactic, summary,
        queries, findings, recommendations, log_sample,
        hypothesis_id=hypothesis_id, log_source=log_source,
        ingestion_diagnostics=ingestion_diagnostics, hunter_name=hunter_name,
        cover_style=cover_style, sigma_matched_count=sigma_matched_count,
        records_analyzed=records_analyzed,
    )
    return {"report_path": path}


@mcp.tool()
def list_hunt_reports() -> list[dict]:
    """List all generated markdown hunt reports (filename, path, last-modified)."""
    return report.list_reports()


@mcp.tool()
def read_hunt_report(path: str) -> dict:
    """Read the raw markdown content of a previously generated report by
    its path. Restricted to REPORTS_DIR — a path that resolves outside
    it (e.g. via '..' traversal or an absolute path elsewhere on the
    container) is rejected rather than read."""
    try:
        return report.read_report(path)
    except report.ReportPathError as e:
        return {"error": str(e)}
    except OSError as e:
        return {"error": str(e)}


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    port = int(os.environ.get("MCP_PORT", "8100"))
    # Internal Docker-network traffic arrives with a Host header like
    # "mcp:8100" rather than "localhost", which the MCP SDK's DNS-rebinding
    # guard rejects by default (421 Misdirected Request). This is an
    # internal, non-browser-facing service, so we disable that guard here.
    no_rebind_protection = os.environ.get("NO_REBIND_PROTECTION", "0") == "1"
    mcp.run(
        transport=transport,
        host="0.0.0.0",
        port=port,
        host_origin_protection=not no_rebind_protection,
    )
