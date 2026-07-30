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
        "agents": {
            "query_gen": "query",
            "indicator_deriver": "fast",
            "evidence_selector": "reasoning",
            "communication": "fast",
            "chat": "fast",
            "detection_analysis": "fast",
            "investigation_specialist": "reasoning",
            "supervisor": "reasoning",
            "reasoning": "reasoning",
            "coverage_gap": "reasoning",
            "risk_analysis": "reasoning",
            "forensic_planner": "reasoning",
            "forensic_analysis": "reasoning",
            "schedule_planner": "reasoning",
            "hypothesis_prioritizer": "reasoning",
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
            "forensic_planner",
            "forensic_analysis",
            "schedule_planner",
            "hypothesis_prioritizer",
        ],
        "profiles": {
            "query": {"num_ctx": 8192, "num_predict": 1024},
            "fast": {"num_ctx": 8192, "num_predict": 1024},
            "reasoning": {"num_ctx": 16384, "num_predict": 4096},
            "verifier": {"num_ctx": 8192, "num_predict": 2048},
            "coding": {"num_ctx": 16384, "num_predict": 4096},
            "guard": {"num_ctx": 8192, "num_predict": 1024},
        },
    },
    "autonomy": {
        "decision_attempts": 3,
        "reasoning_attempts": 3,
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
        "risk_batch_size": 40,
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
        "coverage_model_record_cap": 12,
        "coverage_record_char_cap": 1800,
        "coverage_decision_num_predict": 640,
        "coverage_decision_attempts": 2,
        "reasoning_model_record_cap": 8,
        "reasoning_record_char_cap": 1400,
        "reasoning_retrieval_attempt_cap": 8,
        "reasoning_context_item_cap": 8,
        "reasoning_decision_num_predict": 512,
    },
    "forensics": {
        "tool_timeout_seconds": 180,
        "tool_output_bytes": 200000,
        "max_static_file_bytes": 2147483648,
        "strings_min_length": 6,
        "capa_rules_dir": "",
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
