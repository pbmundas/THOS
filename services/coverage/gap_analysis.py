"""MITRE ATT&CK-aware telemetry coverage assessment."""
from __future__ import annotations

from collections import Counter
import re

from services.knowledge import mitre
from services.orchestration.state import HuntState


SOURCE_REQUIREMENTS = (
    (re.compile(r"process|command|powershell|script|module", re.I), {"process"}, {"endpoint"}),
    (re.compile(r"auth|kerberos|account|logon|sign-?in|directory", re.I), {"authentication"}, {"identity", "endpoint"}),
    (re.compile(r"dns", re.I), {"dns"}, {"dns", "network"}),
    (re.compile(r"network|flow|packet|socket|connection", re.I), {"network", "dns"}, {"network", "firewall", "ids", "proxy", "endpoint"}),
    (re.compile(r"file|removable|share", re.I), {"file"}, {"endpoint", "email"}),
    (re.compile(r"registry|scheduled|service", re.I), {"registry", "process"}, {"endpoint"}),
    (re.compile(r"email|mail", re.I), {"email", "file"}, {"email"}),
    (re.compile(r"cloud|api|control plane", re.I), {"cloud_control"}, {"cloud"}),
    (re.compile(r"memory|lsass", re.I), {"process", "file"}, {"endpoint"}),
)


def _requirement(source: str) -> tuple[set[str], set[str]]:
    event_categories: set[str] = set()
    device_types: set[str] = set()
    for pattern, categories, devices in SOURCE_REQUIREMENTS:
        if pattern.search(source):
            event_categories.update(categories)
            device_types.update(devices)
    return event_categories, device_types


def _coverage_row(source: str, logs: list[dict]) -> dict:
    required_categories, required_devices = _requirement(source)
    observed_categories = {
        str(item.get("event_category") or "").lower() for item in logs
    }
    observed_devices = {
        str(item.get("device_type") or "").lower() for item in logs
    }
    category_matches = sorted(required_categories & observed_categories)
    device_matches = sorted(required_devices & observed_devices)
    if category_matches:
        status = "covered"
        confidence = "high"
        reason = f"observed required event categories: {', '.join(category_matches)}"
    elif device_matches:
        status = "partial"
        confidence = "medium"
        reason = (
            f"observed relevant device type(s) {', '.join(device_matches)}, "
            "but not the required event category"
        )
    elif not required_categories and not required_devices:
        source_tokens = {
            token for token in re.findall(r"[a-z0-9]+", source.lower())
            if len(token) > 3
        }
        matching_products = sorted({
            str(item.get("source_product") or "")
            for item in logs
            if source_tokens & set(re.findall(
                r"[a-z0-9]+",
                f"{item.get('source_product', '')} {item.get('event_category', '')}".lower(),
            ))
        })
        status = "covered" if matching_products else "unknown"
        confidence = "medium" if matching_products else "low"
        reason = (
            f"source/product fingerprint observed: {', '.join(matching_products)}"
            if matching_products else
            "the local ATT&CK source label has no deterministic telemetry mapping"
        )
    else:
        status = "not_covered"
        confidence = "high"
        reason = (
            "no required event category or device type was observed; expected "
            f"categories={sorted(required_categories)}, devices={sorted(required_devices)}"
        )
    return {
        "data_source": source,
        "status": status,
        "confidence": confidence,
        "required_event_categories": sorted(required_categories),
        "required_device_types": sorted(required_devices),
        "observed_event_categories": category_matches,
        "observed_device_types": device_matches,
        "reason": reason,
    }


async def coverage_gap_node(state: HuntState) -> dict:
    logs = state.get("processed_logs") or []
    events = Counter(str(log.get("event", "unknown")) for log in logs)
    technique_id = str(state.get("technique_id") or "")
    technique = mitre.map_technique(technique_id) or {}
    required_sources = list(technique.get("data_sources") or [])
    rows = [_coverage_row(source, logs) for source in required_sources]
    tested = sum(row["status"] == "covered" for row in rows)
    partial = sum(row["status"] == "partial" for row in rows)
    unavailable = sum(row["status"] == "not_covered" for row in rows)
    status = (
        "covered" if rows and tested == len(rows)
        else "partial" if tested or partial
        else "not_testable" if rows
        else "unknown"
    )
    assessment = {
        "technique_id": technique_id,
        "technique_name": technique.get("name") or state.get("technique_name") or "",
        "status": status,
        "required_source_count": len(rows),
        "covered_source_count": tested,
        "partial_source_count": partial,
        "unavailable_source_count": unavailable,
        "data_sources": rows,
        "observed_device_types": dict(Counter(
            str(log.get("device_type") or "unknown") for log in logs
        )),
        "observed_event_categories": dict(Counter(
            str(log.get("event_category") or "security_event") for log in logs
        )),
    }
    gaps = []
    if state.get("used_fallback_unfiltered"):
        gaps.append("The generated query matched no records; analysis used unfiltered telemetry and should be scoped again.")
    if len(logs) < 10:
        gaps.append(f"Only {len(logs)} normalized record(s) reached analysis; absence conclusions are low confidence.")
    if not events:
        gaps.append("No normalized event types were available; validate collector ingestion and parser support.")
    if state.get("files_scanned") == 0:
        gaps.append("No log files were scanned; verify the selected folder path and allowed roots.")
    for row in rows:
        if row["status"] in {"partial", "not_covered", "unknown"}:
            gaps.append(
                f"ATT&CK {technique_id} telemetry `{row['data_source']}` is "
                f"{row['status'].replace('_', ' ')}: {row['reason']}."
            )
    if technique_id and not required_sources:
        gaps.append(
            f"ATT&CK {technique_id or 'unmapped'} has no governed data-source mapping "
            "in the local technique catalog; coverage is unknown."
        )
    return {"coverage_gaps": gaps, "coverage_assessment": assessment}
