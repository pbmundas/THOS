"""Hardware-aware internal capacity and operator-owned SIEM safety budgets."""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Iterator


LIVE_SIEMS = {"wazuh", "elasticsearch", "splunk", "qradar", "logrhythm"}


def _read_number(path: str) -> int | None:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
        return None if value in {"", "max"} else int(value)
    except (OSError, ValueError):
        return None


def _visible_cpus() -> int:
    detected = max(1, int(os.cpu_count() or 1))
    try:
        affinity = len(os.sched_getaffinity(0))
        detected = min(detected, max(1, affinity))
    except (AttributeError, OSError):
        pass
    try:
        raw = Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf-8").split()
        if len(raw) == 2 and raw[0] != "max":
            detected = min(detected, max(1, math.ceil(int(raw[0]) / int(raw[1]))))
    except (OSError, ValueError, ZeroDivisionError):
        pass
    return detected


def _visible_memory_bytes() -> int:
    cgroup = _read_number("/sys/fs/cgroup/memory.max")
    if cgroup and cgroup < 2**60:
        return cgroup
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return max(1, int(os.environ.get("THOS_VISIBLE_MEMORY_BYTES", str(4 * 1024**3))))


_PROFILES = {
    "compact": {
        "internal_worker_concurrency": 1, "forensic_concurrency": 1,
        "risk_concurrency": 1, "scheduled_sigma_concurrency": 1,
        "scheduled_yara_concurrency": 1, "postgres_pool_max": 4,
    },
    "balanced": {
        "internal_worker_concurrency": 2, "forensic_concurrency": 2,
        "risk_concurrency": 1, "scheduled_sigma_concurrency": 2,
        "scheduled_yara_concurrency": 1, "postgres_pool_max": 8,
    },
    "capable": {
        "internal_worker_concurrency": 4, "forensic_concurrency": 4,
        "risk_concurrency": 2, "scheduled_sigma_concurrency": 4,
        "scheduled_yara_concurrency": 2, "postgres_pool_max": 12,
    },
    "enterprise": {
        "internal_worker_concurrency": 8, "forensic_concurrency": 8,
        "risk_concurrency": 4, "scheduled_sigma_concurrency": 8,
        "scheduled_yara_concurrency": 4, "postgres_pool_max": 20,
    },
}


def hardware_capacity(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the effective capacity inside the container/cgroup boundary."""
    if config is None:
        from services.runtime_config import read_config
        config = read_config()
    settings = config.get("capacity", {}) or {}
    cpus = _visible_cpus()
    memory_bytes = _visible_memory_bytes()
    memory_gb = memory_bytes / 1024**3
    if cpus >= 16 and memory_gb >= 32:
        detected = "enterprise"
    elif cpus >= 8 and memory_gb >= 16:
        detected = "capable"
    elif cpus >= 4 and memory_gb >= 8:
        detected = "balanced"
    else:
        detected = "compact"
    override = str(settings.get("profile_override") or "auto").lower()
    effective = override if override in _PROFILES else detected
    auto_scale = bool(settings.get("auto_scale", True))
    if not auto_scale:
        effective = override if override in _PROFILES else "compact"
    return {
        "auto_scale": auto_scale,
        "detected_profile": detected,
        "effective_profile": effective,
        "logical_cpus_visible": cpus,
        "memory_bytes_visible": memory_bytes,
        "memory_gb_visible": round(memory_gb, 2),
        "recommended": dict(_PROFILES[effective]),
        "basis": "CPU affinity/quota and memory visible inside the container cgroup.",
    }


def internal_worker_limit(workload: str, configured: int | None = None) -> int:
    profile = hardware_capacity()
    if not profile["auto_scale"] and configured is not None:
        return max(1, int(configured))
    recommendation_key = {
        "forensic": "forensic_concurrency",
        "risk": "risk_concurrency",
        "scheduled_sigma": "scheduled_sigma_concurrency",
        "scheduled_yara": "scheduled_yara_concurrency",
        "postgres": "postgres_pool_max",
    }.get(workload, "internal_worker_concurrency")
    recommended = int(profile["recommended"][recommendation_key])
    return recommended


def siem_retrieval_policy(
    source: str,
    requested_limit: int | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the operator-owned ceiling for one SIEM retrieval request."""
    if config is None:
        from services.runtime_config import read_config
        config = read_config()
    source = str(source or "").strip().lower()
    settings = config.get("siem_retrieval", {}) or {}
    source_settings = (settings.get("sources", {}) or {}).get(source, {}) or {}
    is_live = source in LIVE_SIEMS
    default_rows = int(settings.get("default_max_rows", 500) if is_live else settings.get("folder_max_rows", 10000))
    max_rows = max(1, min(10000, int(source_settings.get("max_rows", default_rows))))
    concurrency = max(1, min(32, int(source_settings.get(
        "concurrent_requests", settings.get("default_concurrent_requests", 2),
    ))))
    requested = max(1, int(requested_limit or max_rows))
    return {
        "source": source,
        "requested_rows": requested,
        "max_rows": max_rows,
        "applied_rows": min(requested, max_rows),
        "capped": requested > max_rows,
        "concurrent_requests": concurrency,
        "queue_timeout_seconds": max(1, min(300, int(settings.get("queue_timeout_seconds", 30)))),
        "operator_controlled": is_live,
    }


_SIEM_GATE = threading.Condition()
_SIEM_ACTIVE: dict[str, int] = {}


@contextmanager
def siem_request_slot(policy: dict[str, Any]) -> Iterator[None]:
    """Bound concurrent calls per SIEM, including all MCP callers."""
    source = str(policy["source"])
    maximum = int(policy["concurrent_requests"])
    deadline = time.monotonic() + float(policy["queue_timeout_seconds"])
    with _SIEM_GATE:
        while _SIEM_ACTIVE.get(source, 0) >= maximum:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"SIEM request budget exhausted for {source}; maximum concurrent requests is {maximum}"
                )
            _SIEM_GATE.wait(timeout=remaining)
        _SIEM_ACTIVE[source] = _SIEM_ACTIVE.get(source, 0) + 1
    try:
        yield
    finally:
        with _SIEM_GATE:
            _SIEM_ACTIVE[source] = max(0, _SIEM_ACTIVE.get(source, 1) - 1)
            _SIEM_GATE.notify_all()
