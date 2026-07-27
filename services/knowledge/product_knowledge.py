"""Versioned, dependency-free product knowledge for Ask THOS.

This catalog covers stable product behavior that should not depend on model
weights or on whether an analyst has uploaded documentation.  Agent entries
are generated from the canonical registry so runtime ownership, testing, and
assistant answers stay aligned.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from services.agents.registry import AGENT_SPECS


@dataclass(frozen=True)
class ProductTopic:
    id: str
    title: str
    content: str
    keywords: tuple[str, ...]
    source: str


_STATIC_TOPICS: tuple[ProductTopic, ...] = (
    ProductTopic(
        "PK-OVERVIEW", "What THOS is",
        "THOS is an on-premises Threat Hunting Operating System for hypothesis-driven hunts. It orchestrates specialized agents through LangGraph, exposes governed capabilities through an authenticated MCP service, uses local model inference, and keeps SIEM, model, database, Redis, and vector-store services on the internal Docker network. The browser talks to the governed API, not directly to the model or MCP service.",
        ("overview", "architecture", "what is thos", "on premises", "agentic platform"),
        "README.md; THOS-Developer-Guide.md sections 1-2",
    ),
    ProductTopic(
        "PK-HUNT", "Running a threat hunt",
        "Choose a curated or organizational hypothesis, select an active SIEM, direct integration, or folder telemetry source, choose the report audience, and start one hunt. THOS serializes hunts platform-wide, streams named-agent updates with local timestamps and model metadata, permits bounded evidence-based replanning and a configured targeted reasoning follow-up, verifies every finding citation, and then writes a report. A negative result with weak telemetry is reported as a coverage limitation rather than proof of absence.",
        ("hunt", "hypothesis", "start", "workflow", "progress", "follow up"),
        "README.md; services/orchestration/graph.py",
    ),
    ProductTopic(
        "PK-SOURCES", "Supported telemetry and SIEM sources",
        "The Integrations page manages local folder evidence, Wazuh, LogRhythm, Splunk, QRadar, and configurable read-only API connectors for common EDR/XDR, identity, cloud, email, network, and generic security telemetry. Folder mode parses known logs under configured allowed roots, including EVTX, log/syslog, CSV/TSV, CEF/LEEF, JSON/ECS, XML, text, and PCAP. Every other regular file receives bounded artifact metadata, magic, sample hashing, and printable-string triage rather than being ignored. Mixed SIEM results are attributed to source vendor, product, device type, and event category with an auditable confidence and basis. Live credentials remain server-side.",
        ("integration", "edr", "xdr", "siem", "wazuh", "logrhythm", "splunk", "qradar", "folder", "evtx", "pcap", "telemetry", "schema", "device type"),
        "services/integrations; services/siem/attribution.py; services/ui/src/Integrations.jsx",
    ),
    ProductTopic(
        "PK-DETECTIONS", "Detection rules and scheduled detection",
        "THOS pins its community detection-rule and Yara-Rules/rules corpora to exact commits. Detection rules are compiled into vendor queries and validated against discovered SIEM fields. YARA community files are isolated, compiler-validated, and assembled into one reusable catalog; incompatible legacy files remain visible as quarantined instead of disabling ready rules. Local and community YARA rules can be searched, severity-filtered, enabled, disabled, manually scanned against managed evidence, or scheduled with file-size, file-count, match-count, and timeout bounds. Scheduled detections store outcomes and may create deterministic triage cases. Draft detection rules are never promoted automatically; validate them through the organization's detection change-control process.",
        ("yara", "rule", "detection", "schedule", "compile", "uncompilable", "promotion", "deduplicate", "malware"),
        "README.md schema-aware scheduled detection; services/detection",
    ),
    ProductTopic(
        "PK-KNOWLEDGE", "Knowledge sources and RAG",
        "Built-in product knowledge answers how THOS itself works. The governed hypothesis catalog supplies hunting hypotheses, the local MITRE table supplies technique metadata, SIEM knowledge supplies field mappings, and the custom organizational knowledge base stores uploaded playbooks, runbooks, advisories, and prior write-ups. Uploading documents grounds retrieval; it does not retrain model weights. Product knowledge, governed cybersecurity references, and organizational documents remain distinct provenance-labelled sources.",
        ("knowledge", "rag", "upload", "document", "hypothesis", "mitre", "playbook", "runbook", "training"),
        "README.md; THOS-Developer-Guide.md section 6.6",
    ),
    ProductTopic(
        "PK-ASK", "Ask THOS behavior and limits",
        "Ask THOS uses the configured fast-tier local model, temporary analyst-scoped conversation memory, this built-in product catalog, governed cybersecurity retrieval, and authorized read-only tools. According to the user's role and feature grants, it can list and read hunt runs, forensic cases, named-agent stages, model metadata, and generated reports. For deeper interpretation it delegates the grounded state to either the Hunt Investigation Specialist Agent or Digital Forensic Specialist Agent and shows that agent's model and duration. It can also search organizational documents and hypotheses, read SIEM field mappings, and list allowed evidence files. It cannot contain hosts, change evidence, change connector configuration, promote detections, or claim a tool or specialist result that was not returned.",
        ("ask thos", "assistant", "chat", "investigation", "hunt state", "forensic state", "delegate", "specialist", "tool", "memory", "limit"),
        "services/chat_agent.py; services/memory/chat_memory.py",
    ),
    ProductTopic(
        "PK-GOVERNANCE", "Safety, analyst review, cases, and audit",
        "Untrusted telemetry is canonicalized across Unicode, HTML, URL, Base64, and hexadecimal representations, scored by semantic heuristics, and ambiguous content is classified by a dedicated guard-tier adversarial model. High-risk fields are quarantined only in the reasoning view while original evidence remains available to deterministic tools and audit. Findings must cite actual record references or the event histogram. Failed, degraded, or repaired verification is marked for analyst review and can open a case. Draft detection content stays experimental and THOS performs no autonomous containment.",
        ("security", "guardrail", "verification", "review", "case", "audit", "containment", "prompt injection"),
        "services/guardrails; services/verification; services/detection_engineering",
    ),
    ProductTopic(
        "PK-REPORTS", "Reports and audiences",
        "The Reports page classifies and filters Hunt and Forensic reports separately. Its dynamic time-period control supports the last 1-31 days, 1-12 months, 1-10 years, or all time. Hunt reports contain hypothesis and ATT&CK context, queries, ingestion diagnostics, evidence, detection-rule matches, reasoning, verification, gaps, and governance references. Forensic reports contain custody, hashes, methodology, artifact inventory, correlations, timeline, limitations, and legal-review requirements. Administrators can clear hunt-run audit history and remove reports from the active library; report deletion moves the file into a server-side recovery archive.",
        ("report", "executive", "soc analyst", "compliance", "findings", "evidence"),
        "services/reporting/report.py; services/forensics/report.py; services/api/ui_gateway.py",
    ),
    ProductTopic(
        "PK-RISKS", "Actionable Risks page and Risk Analysis Agent",
        "The Risk Analysis Agent deterministically correlates verifier-supported Security Findings from hunt reports with scheduled detections that matched events. It excludes unverified report claims, consolidates repeated risk/entity pairs, and assigns an explainable 0-100 score and critical, high, medium, or low severity without consuming a model worker. The Risks page shows what the risk is, why it matters, how it was discovered, the affected host, user, IP, technique, or telemetry source, its first-identified age, and a direct link to the originating report or detection. It does not perform containment or declare intent.",
        ("risk", "risks", "score", "severity", "entity", "age", "impact", "risk analysis"),
        "services/risk/risk_agent.py; services/ui/src/Risks.jsx",
    ),
    ProductTopic(
        "PK-FORENSICS", "Digital forensic examination",
        "The Forensics menu accepts one or more evidence files. THOS stores originals under data/log_sources/forensic/<UTC date>/<date-serial-case>, hashes each file during intake, writes a chain-of-custody manifest, marks originals read-only where supported, and recomputes size and full SHA-256 before analysis. Named deterministic agents inventory and parse artifacts, evaluate pinned community and local detection rules, scan managed files with enabled YARA rules, correlate observed values with the shared IOC index, summarize ATT&CK techniques represented by matching rules, assess suspicious or corroborated malicious activity, reconstruct a referenced classification-aware timeline, and write a technical report with legal-review requirements. E01/Ex01 and raw-image metadata use installed ewf-tools and Sleuth Kit; unavailable or opaque decoders are reported as limitations, never treated as completed examination.",
        ("forensic", "forensics", "evidence intake", "chain of custody", "encase", "e01", "disk image", "hash", "timeline", "yara", "malicious activity"),
        "services/forensics; services/api/ui_gateway.py",
    ),
    ProductTopic(
        "PK-ACCESS", "Users, roles, and access",
        "Admin users control all platform features, account administration, report deletion, hunt-history clearing, and the compact platform logo shown in the top bar. SME users have full operational UI access without destructive account/report or platform-branding controls. Expert users have hunting, investigation, reports, chat, knowledge, and read-only Threat Intelligence access. Every user can update their account display name, email, password, and avatar; the immutable sign-in username is separate from the account name. Secrets and connector credentials remain server-side and are not returned to the browser.",
        ("user", "role", "expert", "admin", "sme", "permission", "account name", "email", "password", "avatar", "login", "credential", "secret"),
        "README.md access control; services/api/control_plane.py",
    ),
    ProductTopic(
        "PK-IOC", "IOC source management",
        "The Configuration page lets Admin and SME users add remote threat-intelligence file URLs, upload local files, set category, severity, and confidence, enable or disable schedules, fetch a specific source manually, or refresh all enabled sources sequentially. Five reviewed workbook-derived feeds are installed once with staggered schedules: OpenPhish, Feodo Tracker recommended C2, Tor exits, DShield block data, and FireHOL Level 1. The deterministic IOC Management Agent revalidates every redirect against SSRF policy, enforces timeout, byte, indicator, total-index, and snapshot-retention limits, removes source-expired indicators after successful refresh, and atomically rebuilds rich provenance metadata. The Threat Intelligence page gives all operational roles a searchable catalog ordered by freshness, severity, category, and type. The same index enriches hunts and forensic evidence; collection does not by itself authorize blocking or prove maliciousness.",
        ("ioc", "indicator", "threat intelligence", "feed", "source", "fetch", "schedule", "blocklist", "stix"),
        "services/enrichment/ioc_management.py; services/api/control_plane.py",
    ),
    ProductTopic(
        "PK-RESOURCES", "Quality and resource controls",
        "THOS reduces resource use with deterministic agents where a model is unnecessary, bounded SIEM result limits, SIEM-side detection-rule pushdown, cached schemas and reasoning, parallel independent tools, one targeted follow-up by default, and three-strike local-model fallbacks. Quality is protected with schema validation, evidence citations, deterministic verification, fail-closed compilation, case tracking, audit records, and layered automated tests.",
        ("resource", "performance", "quality", "cost", "cpu", "memory", "cache", "model strikes"),
        "services/orchestration; services/reasoning; services/detection",
    ),
    ProductTopic(
        "PK-TESTING", "Testing every agent",
        "Run the dependency-free contract harness first, then focused agent and product-knowledge tests, then the complete pytest suite. Contract checks verify every registered module, callable, graph node, and mapped test file. Behavior tests use deterministic fixtures and mocks. Live acceptance additionally requires the Docker stack, model, Redis, PostgreSQL, ChromaDB, MCP, and at least one configured telemetry source; live failures must not be confused with offline contract failures.",
        ("test", "testing", "validate", "agent test", "contract", "pytest", "smoke", "acceptance"),
        "services/validation/agent_harness.py; docs/AGENT-TESTING.md",
    ),
    ProductTopic(
        "PK-TROUBLESHOOT", "Troubleshooting order",
        "Check Docker service health first, then MCP authentication, model availability, Redis and PostgreSQL connectivity, Chroma collections, SIEM credentials, and the selected telemetry path. Use ingestion diagnostics to distinguish no matching events from no data. Schema-aware compilation errors identify missing vendor fields or unsupported backends and should be fixed rather than bypassed.",
        ("troubleshoot", "error", "failed", "health", "docker", "no data", "connection"),
        "README.md; THOS-Developer-Guide.md operations sections",
    ),
)

_STOP_WORDS = {
    "a", "an", "and", "are", "can", "do", "does", "for", "from", "how",
    "i", "in", "is", "it", "me", "of", "on", "or", "the", "to", "what",
    "when", "where", "which", "with", "you",
}
_PRODUCT_MARKERS = {
    "thos", "agent", "platform", "product", "hunt", "hypothesis", "siem",
    "detection", "schedule", "report", "knowledge", "rag", "upload",
    "setting", "configure", "review", "case", "role", "permission", "test",
    "docker", "telemetry", "schema", "ask", "forensic", "forensics", "evidence",
    "ioc", "indicator", "account", "avatar",
}

REQUIRED_USER_TOPIC_IDS = frozenset({
    "PK-OVERVIEW", "PK-HUNT", "PK-SOURCES", "PK-DETECTIONS", "PK-KNOWLEDGE",
    "PK-ASK", "PK-GOVERNANCE", "PK-REPORTS", "PK-ACCESS", "PK-RESOURCES",
    "PK-TESTING", "PK-TROUBLESHOOT", "PK-FORENSICS", "PK-IOC",
})


def _agent_topics() -> tuple[ProductTopic, ...]:
    return tuple(
        ProductTopic(
            id=f"PK-AGENT-{agent.id.upper().replace('_', '-')}",
            title=agent.name,
            content=(
                f"{agent.purpose} Execution: {agent.execution}. Resource profile: "
                f"{agent.resource_profile}. Safety boundary: {agent.safety_boundary}. "
                f"Implementation: {agent.module}.{agent.callable}. Regression coverage: {agent.test_file}."
            ),
            keywords=(agent.id.replace("_", " "), agent.name.lower(), agent.graph_node or ""),
            source=f"{agent.module}; {agent.test_file}",
        )
        for agent in AGENT_SPECS
    )


def all_product_topics() -> tuple[ProductTopic, ...]:
    return _STATIC_TOPICS + _agent_topics()


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9][a-z0-9_.-]*", value.lower())
        if token not in _STOP_WORDS and len(token) > 1
    }


def is_product_question(query: str) -> bool:
    lowered = query.lower()
    tokens = _tokens(query)
    return "ask thos" in lowered or bool(tokens & _PRODUCT_MARKERS)


def search_product_knowledge(query: str, limit: int = 6) -> list[dict]:
    """Return ranked, citation-ready product topics without external services."""
    query_text = query.strip().lower()
    query_tokens = _tokens(query)
    ranked: list[tuple[int, ProductTopic]] = []
    for topic in all_product_topics():
        title = topic.title.lower()
        content = topic.content.lower()
        keyword_text = " ".join(topic.keywords).lower()
        title_tokens = _tokens(title)
        keyword_tokens = _tokens(keyword_text)
        content_tokens = _tokens(content)
        score = 0
        if query_text and query_text in f"{title} {keyword_text} {content}":
            score += 12
        score += 6 * len(query_tokens & title_tokens)
        score += 4 * len(query_tokens & keyword_tokens)
        score += len(query_tokens & content_tokens)
        for phrase in topic.keywords:
            if phrase and phrase in query_text:
                score += 8
        if score:
            ranked.append((score, topic))
    if not ranked:
        ranked = [(1, topic) for topic in _STATIC_TOPICS[:2]]
    ranked.sort(key=lambda item: (-item[0], item[1].id))
    return [
        {
            "id": topic.id,
            "title": topic.title,
            "content": topic.content,
            "source": topic.source,
            "score": score,
        }
        for score, topic in ranked[:max(1, min(limit, 10))]
    ]


def product_context(query: str, limit: int = 6, max_chars: int = 12_000) -> tuple[str, list[dict]]:
    hits = search_product_knowledge(query, limit=limit) if is_product_question(query) else []
    sections = [
        f"[{item['id']}] {item['title']}\n{item['content']}\nSource: {item['source']}"
        for item in hits
    ]
    return "\n\n".join(sections)[:max_chars], [
        {"id": item["id"], "title": item["title"], "source": item["source"]}
        for item in hits
    ]
