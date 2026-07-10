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
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic: Optional[str]

    # Set by query_generator node
    query: Optional[str]

    # Set by siem_fetch node
    logs: List[Dict[str, Any]]
    record_count: int
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
    need_more_logs: bool
    follow_up_query: Optional[str]

    # Set by report node
    report_path: Optional[str]

    # Bookkeeping
    iteration: int
    max_iterations: int
    error: Optional[str]
