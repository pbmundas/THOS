"""Data-driven SIEM field mappings used to ground query generation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from services.runtime_config import get_value


_MAPPING_PATH = Path(__file__).with_name("data") / "default_field_mappings.json"


@lru_cache(maxsize=1)
def _default_field_map() -> dict:
    loaded = json.loads(_MAPPING_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuntimeError("SIEM field mapping catalog must contain an object")
    return loaded


def get_field_mapping(siem_type: str) -> dict:
    """Return normalized-to-vendor fields plus runtime/schema overrides."""
    key = siem_type.lower()
    mapping = dict(_default_field_map().get(key, {}))
    custom = get_value("siem_field_mappings", key, default={})
    if isinstance(custom, dict):
        mapping.update({
            str(field): str(value)
            for field, value in custom.items()
            if str(field) and str(value)
        })
    inventory = get_value("siem_field_inventory", key, default={})
    fields = inventory.get("fields", []) if isinstance(inventory, dict) else []
    if isinstance(fields, list) and fields:
        mapping["available_fields"] = ", ".join(
            str(field) for field in fields if str(field).strip()
        )
    return mapping


def get_field_capabilities() -> dict[str, list[str]]:
    """Return vendor-neutral telemetry capabilities by normalized field."""
    configured = _default_field_map().get("_normalized_capabilities", {})
    if not isinstance(configured, dict):
        return {}
    return {
        str(field): [
            str(capability)
            for capability in capabilities
            if str(capability).strip()
        ]
        for field, capabilities in configured.items()
        if isinstance(capabilities, list)
    }


def get_field_value_kinds() -> dict[str, list[str]]:
    """Return governed literal kinds accepted by each normalized field."""
    configured = _default_field_map().get("_normalized_value_kinds", {})
    if not isinstance(configured, dict):
        return {}
    return {
        str(field): [
            str(kind)
            for kind in kinds
            if str(kind).strip()
        ]
        for field, kinds in configured.items()
        if isinstance(kinds, list)
    }


def get_field_query_priorities() -> dict[str, int]:
    """Return data-configured retrieval priority by normalized field."""
    configured = _default_field_map().get("_normalized_query_priority", {})
    if not isinstance(configured, dict):
        return {}
    output: dict[str, int] = {}
    for field, priority in configured.items():
        try:
            output[str(field)] = max(0, min(100, int(priority)))
        except (TypeError, ValueError):
            continue
    return output


def normalize_field(siem_type: str, normalized_field: str) -> str | None:
    return get_field_mapping(siem_type).get(normalized_field)
