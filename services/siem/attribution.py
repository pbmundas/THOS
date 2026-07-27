"""Deterministic source, product, device, and event-category attribution.

Live SIEMs frequently mix endpoint, identity, firewall, DNS, cloud, and SaaS
events in the same result set. This module preserves explicit vendor metadata
when present and otherwise applies auditable fingerprints. It never presents a
low-confidence inference as a verified fact.
"""
from __future__ import annotations

from collections import Counter
import json
import re
from typing import Any


WINDOWS_EVENT_IDS = {
    "4624", "4625", "4634", "4648", "4672", "4688", "4689", "4697", "4698",
    "4720", "4728", "4732", "4768", "4769", "4771", "4776", "7045", "4103",
    "4104", "1102",
}

FINGERPRINTS = [
    (re.compile(r"\b(crowdstrike|falcon)\b", re.I), "CrowdStrike", "Falcon", "endpoint"),
    (re.compile(r"\b(sentinelone|deep visibility)\b", re.I), "SentinelOne", "SentinelOne", "endpoint"),
    (re.compile(r"\b(cortex xdr|xdr_data|palo alto)\b", re.I), "Palo Alto Networks", "Cortex / PAN-OS", "firewall"),
    (re.compile(r"\b(carbon black|cb defense|cb response)\b", re.I), "Broadcom", "Carbon Black", "endpoint"),
    (re.compile(r"\b(microsoft defender|defender for endpoint|mdatp|advanced hunting)\b", re.I), "Microsoft", "Defender XDR", "endpoint"),
    (re.compile(r"\b(sysmon|microsoft-windows-sysmon)\b", re.I), "Microsoft", "Sysmon", "endpoint"),
    (re.compile(r"\b(suricata|eve\.json)\b", re.I), "Open Information Security Foundation", "Suricata", "ids"),
    (re.compile(r"\b(zeek|conn\.log|dns\.log|http\.log)\b", re.I), "Zeek Project", "Zeek", "network"),
    (re.compile(r"\b(okta|system\.log)\b", re.I), "Okta", "Okta", "identity"),
    (re.compile(r"\b(cloudtrail|guardduty|aws\.)\b", re.I), "Amazon Web Services", "AWS Security", "cloud"),
    (re.compile(r"\b(azureactivity|entra|aad sign-?in)\b", re.I), "Microsoft", "Azure / Entra", "cloud"),
    (re.compile(r"\b(fortigate|fortinet)\b", re.I), "Fortinet", "FortiGate", "firewall"),
    (re.compile(r"\b(check point|checkpoint)\b", re.I), "Check Point", "Security Gateway", "firewall"),
    (re.compile(r"\b(cisco asa|firepower|ftd)\b", re.I), "Cisco", "Firewall", "firewall"),
    (re.compile(r"\b(zscaler|web proxy|proxy)\b", re.I), "Unknown", "Web Proxy", "proxy"),
]


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
    if any(marker in lowered for marker in ("process", "4688", "sysmon event id 1", "commandline")):
        return "process"
    if any(marker in lowered for marker in ("login", "logon", "auth", "4624", "4625", "signin")):
        return "authentication"
    if any(marker in lowered for marker in ("dns", "domain query")):
        return "dns"
    if any(marker in lowered for marker in ("file", "hash", "malware", "quarantine")):
        return "file"
    if any(marker in lowered for marker in ("registry", "reg_key", "regvalue")):
        return "registry"
    if any(marker in lowered for marker in ("network", "connection", "flow", "src_ip", "dst_ip")):
        return "network"
    if any(marker in lowered for marker in ("email", "mail", "phish")):
        return "email"
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

    if not (vendor and product and device_type):
        for pattern, matched_vendor, matched_product, matched_type in FINGERPRINTS:
            if pattern.search(sample):
                vendor = vendor or matched_vendor
                product = product or matched_product
                device_type = device_type or matched_type
                confidence = "high" if explicit_vendor or explicit_product else "medium"
                basis = f"matched {matched_product} telemetry fingerprint"
                break

    if event in WINDOWS_EVENT_IDS or re.search(r"\bwindows\b|\bwinlog\b", sample, re.I):
        vendor = vendor or "Microsoft"
        product = product or "Windows Security"
        device_type = device_type or ("identity" if event in {"4768", "4769", "4771", "4776"} else "endpoint")
        confidence = "high" if event in WINDOWS_EVENT_IDS else "medium"
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

