"""Deterministic source, product, device, and event-category attribution.

Live SIEMs frequently mix endpoint, identity, firewall, DNS, cloud, and SaaS
events in the same result set. This module preserves explicit vendor metadata
when present and otherwise applies auditable fingerprints. It never presents a
low-confidence inference as a verified fact.
"""
from __future__ import annotations

from collections import Counter
from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any


_CATALOG_PATH = Path(__file__).with_name("data") / "attribution_catalog.json"


@lru_cache(maxsize=1)
def _catalog() -> dict:
    loaded = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuntimeError("telemetry attribution catalog must contain an object")
    return loaded


def _nested(record: dict, *paths: str):
    for path in paths:
        value: Any = record
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value not in (None, ""):
            return value
    return None


def _event_category(event: str, text: str, device_type: str) -> str:
    lowered = f"{event} {text}".lower()
    for rule in _catalog().get("event_categories", []):
        if any(str(marker).lower() in lowered for marker in rule.get("markers", [])):
            return str(rule.get("category") or "security_event")
    if device_type == "cloud":
        return "cloud_control"
    return "security_event"


def attribute_record(record: dict, collector: str = "") -> dict:
    result = dict(record)
    raw = record.get("_raw") if isinstance(record.get("_raw"), dict) else record
    explicit_vendor = _nested(
        raw, "source_vendor", "observer.vendor", "event.vendor",
        "device.vendor", "vendor", "data.win.system.providerName",
    )
    explicit_product = _nested(
        raw, "source_product", "observer.product", "event.module",
        "device.product", "product", "service.name", "source_type",
    )
    explicit_type = _nested(raw, "device_type", "observer.type", "event.dataset", "log_type")
    event = str(record.get("event") or _nested(raw, "event.code", "event.id", "winlog.event_id") or "")
    sample = json.dumps(raw, ensure_ascii=False, default=str)[:20_000]

    vendor = str(explicit_vendor or "").strip()
    product = str(explicit_product or "").strip()
    device_type = str(explicit_type or "").strip().lower()
    confidence = "high" if vendor and product else "low"
    basis = "explicit vendor/product fields" if confidence == "high" else "no reliable product fingerprint"

    catalog = _catalog()
    if not (vendor and product and device_type):
        for fingerprint in catalog.get("fingerprints", []):
            if re.search(str(fingerprint.get("pattern") or r"(?!x)x"), sample, re.I):
                vendor = vendor or str(fingerprint.get("vendor") or "Unknown")
                product = product or str(fingerprint.get("product") or "Unknown")
                device_type = device_type or str(fingerprint.get("device_type") or "unknown")
                confidence = "high" if explicit_vendor or explicit_product else "medium"
                basis = f"matched {product} telemetry fingerprint"
                break

    windows_ids = {str(value) for value in catalog.get("windows_event_ids", [])}
    identity_ids = {
        str(value) for value in catalog.get("windows_identity_event_ids", [])
    }
    if event in windows_ids or re.search(r"\bwindows\b|\bwinlog\b", sample, re.I):
        vendor = vendor or "Microsoft"
        product = product or "Windows Security"
        device_type = device_type or ("identity" if event in identity_ids else "endpoint")
        confidence = "high" if event in windows_ids else "medium"
        basis = f"recognized Windows event {event}" if event else "matched Windows log fields"

    if not device_type:
        if record.get("src_ip") or record.get("dst_ip"):
            device_type = "network"
            basis = "network address fields present"
        else:
            device_type = "unknown"
    product = product or "Unknown"
    vendor = vendor or "Unknown"
    category = _event_category(event, sample, device_type)

    result.update({
        "source_vendor": vendor,
        "source_product": product,
        "device_type": device_type,
        "event_category": category,
        "event_dataset": str(_nested(raw, "event.dataset", "data_stream.dataset", "sourcetype") or ""),
        "host_id": str(_nested(raw, "host.id", "agent.id", "device.id", "device_id") or ""),
        "os_family": str(_nested(raw, "host.os.family", "os.family", "platform") or ""),
        "collector": collector or str(_nested(raw, "collector", "observer.name", "agent.name") or ""),
        "original_source": str(record.get("source_type") or collector or ""),
        "attribution_confidence": confidence,
        "attribution_basis": basis,
    })
    return result


def telemetry_profile(records: list[dict]) -> dict:
    return {
        "record_count": len(records),
        "device_types": dict(Counter(item.get("device_type", "unknown") for item in records)),
        "products": dict(Counter(item.get("source_product", "Unknown") for item in records)),
        "event_categories": dict(Counter(item.get("event_category", "security_event") for item in records)),
        "low_confidence_records": sum(
            item.get("attribution_confidence") == "low" for item in records
        ),
    }
