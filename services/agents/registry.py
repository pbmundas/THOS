"""Single source of truth for THOS agent ownership, contracts, and tests.

The registry deliberately stores import paths instead of importing agent
implementations.  Product-knowledge retrieval and contract validation can
therefore run without starting LangGraph, a SIEM, a model, or a database.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentSpec:
    id: str
    name: str
    purpose: str
    module: str
    callable: str
    test_file: str
    graph_node: str | None = None
    model_route: str | None = None
    execution: str = "deterministic"
    resource_profile: str = "CPU-light"
    safety_boundary: str = "Read-only"


AGENT_SPECS: tuple[AgentSpec, ...] = (
    AgentSpec(
        "ask_thos", "Ask THOS Agent",
        "Helps users investigate authorized hunt and forensic state, answers product and SOC questions, and delegates evidence interpretation to specialist agents.",
        "services.chat_agent", "chat", "tests/agents/test_agent_behaviors.py",
        model_route="chat", execution="local LLM + retrieval", resource_profile="One fast-tier local-model call, plus one follow-up only when tools are required",
    ),
    AgentSpec(
        "hunt_investigation_specialist", "Hunt Investigation Specialist Agent",
        "Answers follow-up questions from persisted hunt state, agent outputs, ATT&CK coverage, and the generated report without changing the hunt.",
        "services.chat_agent", "_delegate_specialist", "tests/agents/test_agent_behaviors.py",
        model_route="investigation_specialist", execution="delegated local LLM + persisted evidence",
        safety_boundary="Read-only; report and hunt content are treated as untrusted data",
    ),
    AgentSpec(
        "forensic_investigation_specialist", "Digital Forensic Specialist Agent",
        "Answers follow-up questions from persisted forensic state, integrity results, suspicious-activity assessment, timeline, and technical report.",
        "services.chat_agent", "_delegate_specialist", "tests/agents/test_agent_behaviors.py",
        model_route="investigation_specialist", execution="delegated local LLM + persisted evidence",
        safety_boundary="Read-only; never modifies original evidence or asserts unsupported attribution",
    ),
    AgentSpec(
        "knowledge_refresh", "Hypothesis Knowledge Refresh Agent",
        "Refreshes hunting hypotheses at most once per configured TTL and never blocks a hunt when the upstream source is unavailable.",
        "services.hunting.kb_refresh", "refresh_hearth_kb_node", "tests/agents/test_agent_behaviors.py",
        graph_node="refresh_hearth_kb", execution="MCP I/O", safety_boundary="Read-only external fetch and local KB upsert",
    ),
    AgentSpec(
        "hypothesis", "Hypothesis Agent",
        "Selects a supplied or semantically relevant hunting hypothesis and grounds it in local MITRE ATT&CK metadata.",
        "services.hunting.hypothesis", "select_hypothesis", "tests/agents/test_agent_behaviors.py",
        graph_node="hypothesis", execution="retrieval",
    ),
    AgentSpec(
        "hunt_memory", "Hunt Memory Agent",
        "Recalls recent hunts for the selected ATT&CK technique so analysts can reuse prior context without mixing users or evidence.",
        "services.memory.hunt_memory", "recall_hunt_memory_node", "tests/agents/test_agent_behaviors.py",
        graph_node="hunt_memory", execution="database read",
    ),
    AgentSpec(
        "supervisor", "Supervisor Agent",
        "Creates the initial source-aware hunt objective, source priority, lookback, and result budget from the hypothesis and available telemetry.",
        "services.orchestration.supervisor", "plan_hunt_node", "tests/orchestration/test_agentic_foundations.py",
        graph_node="supervisor", model_route="supervisor",
        execution="local LLM + validation",
    ),
    AgentSpec(
        "query_generation", "Query Generation Agent",
        "Generates and validates one dialect-specific query for each governed investigation step and selected telemetry source.",
        "services.hunting.query_gen", "generate_query_node", "tests/reasoning/test_wazuh_query_generation.py",
        graph_node="query_gen", model_route="query_gen", execution="local LLM + validation",
    ),
    AgentSpec(
        "siem_fetch", "SIEM Fetch Agent",
        "Executes bounded queries against configured SIEM or folder sources, rejects duplicate refinements, and records ingestion diagnostics.",
        "services.siem.siem_fetch", "fetch_logs_node", "tests/siem/test_siem_cache.py",
        graph_node="siem_fetch", execution="MCP I/O",
    ),
    AgentSpec(
        "log_processing", "Log Processing Agent",
        "Normalizes and deduplicates telemetry before any reasoning-capable stage sees it.",
        "services.siem.log_processing", "process_logs_node", "tests/agents/test_agent_behaviors.py",
        graph_node="log_processing",
    ),
    AgentSpec(
        "guardrail", "Guardrail Agent",
        "Flags instruction-like text in untrusted telemetry without deleting evidence.",
        "services.guardrails.sentinel", "guardrail_node", "tests/orchestration/test_agentic_foundations.py",
        graph_node="guardrail", model_route="guardrail",
        execution="canonicalization + semantic heuristics + bounded local classifier",
        safety_boundary="Read-only; suspicious evidence remains auditable",
    ),
    AgentSpec(
        "soc_tools", "SOC Tools Agent",
        "Runs detection-rule compatibility checks and supplies validated facts to the Evidence Selection Agent, with SIEM-side pushdown where available.",
        "services.mcp.soc_tools", "run_soc_tools_node", "tests/mcp/test_soc_tools.py",
        graph_node="soc_tools", model_route="indicator_deriver", execution="tools + bounded local LLM", resource_profile="Parallel tools; SIEM pushdown minimizes event transfer",
    ),
    AgentSpec(
        "evidence_selector", "Hunt Evidence Selection Agent",
        "Decides which retrieved records contain literal hypothesis-relevant behavior or artifacts and cites their exact record indexes.",
        "services.hunting.evidence_selector", "select_hunt_evidence", "tests/agents/test_evidence_highlights.py",
        model_route="evidence_selector", execution="local LLM + literal-reference validation",
        safety_boundary="May select only supplied records and verbatim literals",
    ),
    AgentSpec(
        "coverage_gap", "Coverage Gap Agent",
        "Assesses whether actual queried telemetry can test every governed ATT&CK data source, with exact record citations and explicit collection gaps.",
        "services.coverage.gap_analysis", "coverage_gap_node", "tests/agents/test_agent_behaviors.py",
        graph_node="coverage_gap", model_route="coverage_gap",
        execution="local LLM + citation validation",
    ),
    AgentSpec(
        "adaptive_replan", "Adaptive Replanning Agent",
        "Uses zero-hit, cap/noise, selected-source, entity-pivot, and ATT&CK coverage context to schedule bounded source-aware retrieval refinements.",
        "services.orchestration.supervisor", "adaptive_replan_node", "tests/orchestration/test_agentic_foundations.py",
        graph_node="adaptive_replan", model_route="supervisor",
        safety_boundary="Bounded refinement budget; selected sources only; every generated query is dialect-validated before execution",
    ),
    AgentSpec(
        "threat_intel", "Threat Intelligence Agent",
        "Matches extracted indicators only against the locally managed IOC blocklist.",
        "services.enrichment.threat_intel", "enrich_iocs_node", "tests/agents/test_agent_behaviors.py",
        graph_node="threat_intel", safety_boundary="Local read-only enrichment; no external reputation lookup",
    ),
    AgentSpec(
        "negative_screening", "Evidence Screening Agent",
        "Stops hunts with zero rule, artifact, IOC, and behavioral evidence before any model reasoning or report generation.",
        "services.reasoning.reasoning", "negative_screening_gate_node",
        "tests/reasoning/test_degraded_model_output.py",
        graph_node="negative_screening_gate",
        execution="deterministic evidence gate",
        resource_profile="CPU-light; prevents unnecessary model and reporting work",
    ),
    AgentSpec(
        "reasoning", "Reasoning Agent",
        "Produces evidence-cited findings and follow-up evidentiary objectives; a separate Query Generation Agent creates the source query.",
        "services.reasoning.reasoning", "reason_node", "tests/reasoning/test_degraded_model_output.py",
        graph_node="reasoning", model_route="reasoning", execution="local LLM + validation", resource_profile="Bounded model strikes and configured follow-ups; no static conclusion fallback",
    ),
    AgentSpec(
        "verifier", "Verifier Agent",
        "Validates exact evidence references, fails report generation on malformed or out-of-range citations, and opens an analyst-review case.",
        "services.verification.verifier", "verify_findings_node", "tests/orchestration/test_agentic_foundations.py",
        graph_node="verifier", safety_boundary="Fail-closed for unsupported claims",
    ),
    AgentSpec(
        "detection_engineering", "Detection Engineering Agent",
        "Drafts an experimental detection-rule proposal only from verifier-passed hunts and records the exact rule hash for change control.",
        "services.detection_engineering.rule_drafter", "draft_detection_rule_node", "tests/orchestration/test_detection_rule_approval.py",
        graph_node="detection_engineering", safety_boundary="Draft only; use normal detection change control before deployment",
    ),
    AgentSpec(
        "communication", "Communication Agent",
        "Adapts one verified evidence set for executive, SOC analyst, or compliance readers without changing the evidence.",
        "services.communication.audience", "communicate_node", "tests/agents/test_agent_behaviors.py",
        graph_node="communication", execution="deterministic evidence-preserving formatting",
    ),
    AgentSpec(
        "report", "Reporting Agent",
        "Writes the final hunt report with evidence, ingestion diagnostics, agent outcomes, and cases.",
        "services.reporting.report", "write_report_node", "tests/orchestration/test_agentic_foundations.py",
        graph_node="report", execution="file write", safety_boundary="Writes only to the configured reports root",
    ),
    AgentSpec(
        "schema_discovery", "SIEM Schema Discovery Agent",
        "Samples bounded recent events, inventories vendor fields, caches a freshness-labelled schema, and reports drift.",
        "services.siem.schema_discovery", "discover_siem_fields", "tests/siem/test_schema_discovery.py",
        execution="SIEM read + cache write", resource_profile="Bounded sample; no full-index schema scan",
    ),
    AgentSpec(
        "scheduled_detection", "Scheduled Detection Agent",
        "Executes precompiled detection queries, deduplicates recurring hits, creates deterministic triage, and persists auditable detection outcomes.",
        "services.detection.sigma_detection_agent", "run_scheduled_sigma_detection", "tests/detection/test_scheduled_detection_dedup.py",
        execution="SIEM read + audit writes", resource_profile="Precompiled queries and bounded result limits",
        safety_boundary="No automatic containment or live-rule promotion",
    ),
    AgentSpec(
        "detection_analysis", "Detection Analysis Agent",
        "Explains one persisted scheduled detection in 5-10 evidence-bounded lines and identifies a concrete validation pivot.",
        "services.detection.detection_analysis_agent", "analyze_detection",
        "tests/detection/test_detection_analysis_agent.py",
        model_route="detection_analysis",
        execution="single local LLM call with schema and evidence validation; fail closed",
        resource_profile="Fast-tier call cached in the detection record after first analysis",
        safety_boundary="Read-only; telemetry is untrusted and rule matches never prove intent, compromise, or attribution",
    ),
    AgentSpec(
        "risk_analysis", "Risk Analysis Agent",
        "Correlates verifier-supported hunt-report findings and matched scheduled detections into an explainable, entity-centered actionable-risk register.",
        "services.risk.risk_agent", "analyze_actionable_risks", "tests/risk/test_risk_agent.py",
        model_route="risk_analysis", execution="local LLM + evidence validation",
        resource_profile="Batched local-model analysis over validated candidates",
        safety_boundary="Read-only; never promotes unverified findings or performs containment",
    ),
    AgentSpec(
        "cyber_knowledge", "Cybersecurity Knowledge Agent",
        "Retrieves provenance-labelled excerpts from the governed primary-source cybersecurity corpus and rejects low-relevance or uncited material.",
        "services.knowledge.cyber_retrieval", "search", "tests/knowledge/test_cyber_corpus.py",
        execution="vector retrieval", resource_profile="Bounded top-k retrieval with lexical and distance gates",
        safety_boundary="Read-only; every excerpt carries publisher, license, retrieval time, and citation ID",
    ),
    AgentSpec(
        "ioc_management", "IOC Management Agent",
        "Fetches configured threat-intelligence files on demand or on schedule, preserves source snapshots, extracts common indicator types, and atomically rebuilds the local IOC index.",
        "services.enrichment.ioc_management", "refresh_source", "tests/enrichment/test_ioc_management.py",
        execution="bounded source I/O + deterministic normalization",
        resource_profile="Streaming size cap with local deduplication",
        safety_boundary="Rejects private-network remote targets by default; writes only to managed intelligence roots",
    ),
    AgentSpec(
        "training_curator", "Training Curator Agent",
        "Builds training-ready examples only from human-verified answers grounded in approved corpus evidence.",
        "services.training.dataset_builder", "build_sft_records", "tests/training/test_dataset_builder.py",
        execution="deterministic offline curation", resource_profile="No model or GPU required",
        safety_boundary="Rejects unlicensed sources, synthetic-unverified examples, and uncited answers",
    ),
    AgentSpec(
        "forensic_intake", "Forensic Intake & Integrity Agent",
        "Validates case containment and chain-of-custody metadata, then recomputes full-file size and SHA-256 before analysis.",
        "services.forensics.analysis", "verify_evidence", "tests/forensics/test_forensic_workflow.py",
        execution="deterministic evidence verification", resource_profile="Streaming full-file hashing",
        safety_boundary="Fails closed on missing evidence, path escape, size drift, or hash mismatch",
    ),
    AgentSpec(
        "forensic_artifact", "Forensic Artifact Analysis Agent",
        "Executes only the validated tool plan, parses supported evidence, and inventories archives without extraction.",
        "services.forensics.analysis", "analyze_artifacts", "tests/forensics/test_forensic_workflow.py",
        execution="planner-directed tool execution", resource_profile="Bounded parsing, commands, and record caps",
        safety_boundary="Read-only originals; archives are inventoried without unsafe extraction",
    ),
    AgentSpec(
        "forensic_planner", "Forensic Planning Agent",
        "Selects available tools and evidentiary objectives per artifact, then performs a second planning pass over first-pass results.",
        "services.forensics.planner", "plan_forensic_tools", "tests/forensics/test_forensic_tools.py",
        model_route="forensic_planner", execution="local LLM + capability validation",
        resource_profile="Two bounded planning calls per case",
        safety_boundary="Can select only installed tools from the governed capability catalog",
    ),
    AgentSpec(
        "forensic_correlation", "Forensic Evidence Correlation Agent",
        "Extracts literal indicators and converts planner-selected tool outputs into cited evidence facts without assigning a verdict.",
        "services.forensics.analysis", "correlate_evidence", "tests/forensics/test_forensic_workflow.py",
        execution="deterministic fact extraction", resource_profile="CPU-bounded local analysis",
        safety_boundary="Produces facts, never an attribution, intent, or maliciousness verdict",
    ),
    AgentSpec(
        "forensic_interpretation", "Forensic Interpretation Agent",
        "Correlates records and tool facts, evaluates alternatives, maps supported ATT&CK behavior, and returns cited proven facts and unresolved anomalies.",
        "services.forensics.interpretation", "interpret_forensic_evidence", "tests/forensics/test_forensic_workflow.py",
        model_route="forensic_analysis", execution="local LLM + evidence-reference validation",
        safety_boundary="Every claim must cite a supplied evidence, record, or fact reference",
    ),
    AgentSpec(
        "forensic_timeline", "Forensic Timeline Agent",
        "Builds a timestamp-ordered reconstruction while preserving evidence and normalized-record references.",
        "services.forensics.analysis", "build_timeline", "tests/forensics/test_forensic_workflow.py",
        execution="deterministic timeline construction", resource_profile="Bounded to 10,000 timeline entries",
        safety_boundary="Does not invent missing timestamps or normalize originals in place",
    ),
    AgentSpec(
        "forensic_report", "Forensic Reporting Agent",
        "Writes a technical digital-forensic report containing integrity, methodology, limitations, evidence references, and legal-review requirements.",
        "services.forensics.report", "write_forensic_report", "tests/forensics/test_forensic_workflow.py",
        execution="deterministic file write", resource_profile="No model call",
        safety_boundary="Writes only to the report root and clearly labels automated observations for human validation",
    ),
    AgentSpec(
        "schedule_planner", "Schedule Planning Agent",
        "Selects and orders maintenance-window hypothesis work from duration history, overdue status, current capacity, and maximum workload.",
        "services.scheduling.planner", "select_scheduled_targets", "tests/orchestration/test_scheduler_frequency.py",
        model_route="schedule_planner", execution="local LLM + capacity validation",
        safety_boundary="Cannot exceed the maintenance window or configured target count",
    ),
)


def agent_by_id(agent_id: str) -> AgentSpec | None:
    return next((agent for agent in AGENT_SPECS if agent.id == agent_id), None)


def graph_agent_nodes() -> set[str]:
    return {agent.graph_node for agent in AGENT_SPECS if agent.graph_node}


def agent_by_graph_node(node_name: str) -> AgentSpec | None:
    return next((agent for agent in AGENT_SPECS if agent.graph_node == node_name), None)
