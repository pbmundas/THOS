"""Small, shared, file-backed runtime control plane for THOS.

The chat gateway is the only writer. MCP and Orchestrator processes read the
same bind-mounted JSON file on every operation, so model, SIEM, field-mapping,
and Sigma changes take effect without rebuilding containers.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import threading
from typing import Any


CONFIG_PATH = Path(os.environ.get("THOS_RUNTIME_CONFIG", "/data/runtime/config.json"))
_LOCK = threading.RLock()

DEFAULT_CONFIG: dict[str, Any] = {
    "general": {"default_iterations": 2, "default_siem": "folder"},
    "models": {"default_model": ""},
    "model_routing": {
        "default_tier": "reasoning",
        "auto_select": False,
        "overrides": {
            "risk_analysis": {"num_predict": 2048},
        },
        "auto_assignments": {},
        "agents": {
            "query_gen": "query",
            "indicator_deriver": "fast",
            "evidence_selector": "fast",
            "communication": "fast",
            "chat": "fast",
            "detection_analysis": "fast",
            "investigation_specialist": "cyber",
            "supervisor": "fast",
            "adaptive_replan": "fast",
            "reasoning": "cyber",
            "coverage_gap": "cyber",
            "risk_analysis": "fast",
            "risk_reconsideration": "cyber",
            "forensic_planner": "cyber",
            "forensic_followup": "cyber",
            "forensic_analysis": "cyber",
            # Scheduling decisions are bounded by deterministic capacity and
            # severity validation, so keep them on the low-latency tier. On a
            # single local GPU this also prevents a background planning tick
            # from loading the 4B model ahead of interactive risk refreshes.
            "schedule_planner": "fast",
            "hypothesis_prioritizer": "fast",
            "verifier": "verifier",
            "detection_engineering": "coding",
            "guardrail": "guard",
        },
        "scheduled_agents": [
            "reasoning",
            "supervisor",
            "evidence_selector",
            "coverage_gap",
            "investigation_specialist",
            "risk_analysis",
            "risk_reconsideration",
            "forensic_planner",
            "forensic_analysis",
            "schedule_planner",
            "hypothesis_prioritizer",
        ],
        "profiles": {
            "query": {"num_ctx": 8192, "num_predict": 1024},
            "fast": {"num_ctx": 8192, "num_predict": 1024},
            "reasoning": {"num_ctx": 16384, "num_predict": 4096},
            "cyber": {"num_ctx": 16384, "num_predict": 2048},
            "verifier": {"num_ctx": 8192, "num_predict": 2048},
            "coding": {"num_ctx": 16384, "num_predict": 4096},
            "guard": {"num_ctx": 8192, "num_predict": 1024},
        },
    },
    "autonomy": {
        "decision_attempts": 3,
        "guardrail_field_char_cap": 2000,
        "guardrail_model_candidate_cap": 8,
        "guardrail_model_value_char_cap": 1000,
        "guardrail_num_predict": 384,
        "guardrail_timeout_seconds": 45,
        "guardrail_transport_retries": 0,
        "reasoning_attempts": 2,
        "query_generation_attempts": 3,
        "supervisor_decision_num_predict": 512,
        "supervisor_memory_item_cap": 4,
        "supervisor_context_item_cap": 8,
        "supervisor_context_char_cap": 1400,
        "max_adaptive_replans": 8,
        "max_reasoning_followups": 2,
        "max_lookback_minutes": 10080,
        "max_query_limit": 2000,
        "default_live_query_limit": 100,
        "default_folder_query_limit": 1000,
        "risk_cache_seconds": 60,
        # One evidence candidate per decision prevents verbose small local
        # models from exhausting the JSON output budget. Fingerprint caching
        # keeps normal report-triggered refreshes incremental and fast.
        "risk_batch_size": 1,
        "risk_batch_concurrency": 1,
        "risk_candidate_cap": 16,
        "risk_prompt_char_cap": 12000,
        "risk_report_context_char_cap": 2000,
        "risk_detection_event_cap": 4,
        "risk_analysis_attempts": 2,
        "risk_analysis_num_predict": 2048,
        "risk_analysis_timeout_seconds": 180,
        "risk_snapshot_limit": 2000,
        "indicator_reference_hit_cap": 3,
        "indicator_reference_char_cap": 2400,
        "indicator_decision_num_predict": 192,
        "indicator_transport_retries": 0,
        "indicator_generation_timeout_seconds": 45,
        "indicator_stage_timeout_seconds": 75,
        "evidence_selection_record_cap": 500,
        "evidence_selection_model_record_cap": 4,
        "evidence_selection_record_char_cap": 1200,
        "evidence_selection_evidence_cap": 3,
        "evidence_selection_num_predict": 384,
        "evidence_selection_attempts": 1,
        "evidence_selection_transport_retries": 0,
        "evidence_selection_timeout_seconds": 120,
        "coverage_model_record_cap": 4,
        "coverage_record_char_cap": 900,
        "coverage_decision_num_predict": 384,
        "coverage_decision_attempts": 1,
        "coverage_decision_timeout_seconds": 120,
        "coverage_transport_retries": 0,
        "supervisor_decision_attempts": 2,
        "supervisor_decision_timeout_seconds": 120,
        "adaptive_replan_attempts": 1,
        "adaptive_replan_timeout_seconds": 90,
        "adaptive_replan_prompt_char_cap": 24000,
        "reasoning_model_record_cap": 4,
        "reasoning_record_char_cap": 900,
        "reasoning_retrieval_attempt_cap": 4,
        "reasoning_context_item_cap": 4,
        "reasoning_kb_chunk_cap": 2,
        "reasoning_kb_char_cap": 400,
        "reasoning_decision_num_predict": 512,
        "reasoning_generation_timeout_seconds": 300,
    },
    "forensics": {
        "tool_timeout_seconds": 180,
        "tool_output_bytes": 200000,
        "max_static_file_bytes": 2147483648,
        "strings_min_length": 6,
        "capa_rules_dir": "",
        "hash_concurrency": 2,
        "artifact_concurrency": 2,
        "tool_concurrency": 4,
        "volatility_plugin_concurrency": 2,
        "planner_attempts": 2,
        "planner_num_predict": 768,
        "planner_timeout_seconds": 120,
        "planner_max_tools_per_artifact": 8,
        "planner_prior_result_cap": 40,
        "planner_prior_char_cap": 1200,
        "followup_attempts": 2,
        "followup_num_predict": 512,
        "followup_timeout_seconds": 90,
        "interpretation_attempts": 2,
        "interpretation_num_predict": 1400,
        "interpretation_timeout_seconds": 240,
        "interpretation_record_cap": 80,
        "interpretation_record_char_cap": 900,
        "interpretation_fact_cap": 120,
        "interpretation_fact_char_cap": 1600,
        "interpretation_inventory_cap": 200,
        "interpretation_plan_artifact_cap": 200,
        "packet_record_cap": 5000,
    },
    "scheduler": {
        "maintenance_start": "00:30",
        "maintenance_window_minutes": 360,
        "maximum_hypotheses_per_window": 24,
        "unobserved_hypothesis_duration_ms": 1200000,
        "detection_start": "23:00",
        "file_scan_start": "22:00",
    },
    "sigma": {"disabled_rule_ids": [], "schedules": []},
    "yara": {"disabled_rule_ids": [], "schedules": []},
    "hypothesis_schedules": [],
    "custom_hypotheses": [],
    "ioc_sources": [],
    "ioc_seed_version": 0,
    "branding": {},
    "siem": {},
    "integrations": {},
    "siem_field_mappings": {},
    "siem_field_inventory": {},
    "maintenance": {
        "schema_refresh_enabled": True,
        "schema_refresh_interval_hours": 168,
        "schema_refresh_retry_hours": 6,
        "schema_refresh_last_started_at": "",
        "schema_refresh_last_completed_at": "",
        "schema_refresh_last_status": "never",
        "schema_refresh_last_error": "",
    },
    "users": [],
}


def _deep_merge(defaults: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(defaults)
    for key, item in (value or {}).items():
        if isinstance(item, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], item)
        else:
            merged[key] = copy.deepcopy(item)
    return merged


def _merge_defaults(value: dict[str, Any]) -> dict[str, Any]:
    return _deep_merge(DEFAULT_CONFIG, value or {})


def read_config() -> dict[str, Any]:
    with _LOCK:
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            return _merge_defaults(raw if isinstance(raw, dict) else {})
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return copy.deepcopy(DEFAULT_CONFIG)


def write_config(config: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        normalized = _merge_defaults(config)
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp = CONFIG_PATH.with_suffix(".tmp")
        temp.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp, CONFIG_PATH)
        return normalized


def update_section(section: str, value: Any) -> dict[str, Any]:
    with _LOCK:
        config = read_config()
        config[section] = value
        return write_config(config)


def get_value(*path: str, default: Any = None) -> Any:
    value: Any = read_config()
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def env_or_runtime(env_name: str, siem_type: str, default: str = "") -> str:
    """Prefer an operator-saved SIEM value, then the container environment."""
    runtime = get_value("siem", siem_type, "settings", env_name, default=None)
    if runtime is not None and str(runtime) != "":
        return str(runtime)
    return os.environ.get(env_name, default)
