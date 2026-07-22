"""
Shared state passed between every LangGraph node.

Extension point: as you add nodes in later phases (e.g. dedicated
enrichment nodes for VirusTotal/OTX, or a human-approval gate before
report publication), just add the fields they need here — LangGraph
merges partial state updates automatically.
"""
from typing import TypedDict, Optional, List, Dict, Any


class HuntState(TypedDict, total=False):
    hunt_id: str
    hunter_name: str
    siem_type: str
    # Only used when siem_type is "folder" — local directory of log
    # artifacts (evtx/log/syslog/csv/CEF/JSON/ECS/xml/txt/pcap) to hunt
    # against instead of a live SIEM API.
    log_source_path: Optional[str]
    log_limit: Optional[int]

    # Set by hypothesis node
    hypothesis_id: Optional[str]
    hypothesis_text: Optional[str]
    hypothesis_tactic: Optional[str]
    hypothesis_technique: Optional[str]
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic: Optional[str]

    # Set by query_generator node
    query: Optional[str]
    query_used_fallback: bool
    query_validation_error: Optional[str]
    executed_queries: List[str]
    max_reasoning_followups: int

    # Set by supervisor / guardrail / verifier agents
    plan: List[str]
    guardrail_result: Dict[str, Any]
    verifier_result: Dict[str, Any]
    human_approval_required: bool
    human_approval_status: Optional[str]
    escalation_reason: Optional[str]

    # Reserved for the next agent increments (enrichment, detection
    # engineering, case management and feedback capture).
    enrichment_hits: List[Dict[str, Any]]
    proposed_detection_rule: Optional[str]
    proposed_detection_rule_hash: Optional[str]
    approval_id: Optional[str]
    case_id: Optional[str]
    coverage_gaps: List[str]
    anomaly_scores: List[Dict[str, Any]]
    hunt_memory: List[Dict[str, Any]]
    communication_summary: Optional[str]

    # Set by siem_fetch node
    logs: List[Dict[str, Any]]
    record_count: int
    total_hits: Optional[int]
    files_scanned: Optional[int]
    total_parsed: Optional[int]
    used_fallback_unfiltered: Optional[bool]

    # Set by log_processing node
    processed_logs: List[Dict[str, Any]]

    # Set by soc_tools node
    sigma_rule: Optional[str]
    sigma_matched_count: int
    sigma_matched_refs: List[int]
    sigma_rule_matches: List[Dict[str, Any]]
    enrichment: Dict[str, Any]

    # Set by caller (HuntRequest) — which report cover page style to render
    cover_style: Optional[str]

    # Set by reasoning node
    reasoning_summary: Optional[str]
    findings: Optional[str]
    recommendations: Optional[str]
    reasoning_cache_hit: bool
    reasoning_failed: bool
    reasoning_degraded: bool
    reasoning_mode: Optional[str]
    reasoning_attempts: int
    reasoning_error: Optional[str]
    need_more_logs: bool
    follow_up_query: Optional[str]

    # Set by report node
    report_path: Optional[str]
    report_status: Optional[str]

    # Bookkeeping
    iteration: int
    max_iterations: int
    error: Optional[str]
