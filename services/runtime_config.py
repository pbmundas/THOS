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
    "general": {"default_iterations": 1, "default_siem": "folder"},
    "models": {"default_model": ""},
    "sigma": {"disabled_rule_ids": [], "schedules": []},
    "hypothesis_schedules": [],
    "custom_hypotheses": [],
    "ioc_sources": [],
    "siem": {},
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


def _merge_defaults(value: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(DEFAULT_CONFIG)
    for key, item in (value or {}).items():
        if isinstance(item, dict) and isinstance(merged.get(key), dict):
            merged[key].update(item)
        else:
            merged[key] = item
    return merged


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
