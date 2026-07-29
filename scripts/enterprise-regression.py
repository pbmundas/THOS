"""Live, bounded enterprise regression probe for THOS.

This harness intentionally does not create synthetic events. It reads the
deployed hypothesis catalog, compiled detection catalog, Wazuh indices, and
managed evidence directory at runtime. It stops increasing search pressure
when the OpenSearch JVM heap crosses the configured safety threshold.

Run this inside the orchestrator container so it uses the same code,
configuration, credentials, and network path as production:

    python /tmp/enterprise-regression.py
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from services.detection.sigma_detection_agent import run_scheduled_sigma_batch
from services.detection.sigma_query_catalog import find_rule, ready_rule_ids
from services.detection.yara_engine import catalog_summary, scan_paths
from services.siem import wazuh


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    value = ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    return round(value, 3)


def _latency_summary(values: list[float]) -> dict[str, Any]:
    return {
        "samples": len(values),
        "min_ms": round(min(values), 3) if values else None,
        "mean_ms": round(statistics.fmean(values), 3) if values else None,
        "p50_ms": _percentile(values, 0.50),
        "p95_ms": _percentile(values, 0.95),
        "max_ms": round(max(values), 3) if values else None,
    }


def _timed(call: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    result = call()
    return result, (time.perf_counter() - started) * 1000


class IndexerClient:
    def __init__(self) -> None:
        cfg = wazuh._get_config()  # use the deployed connector configuration
        self.base_url = cfg["base_url"]
        self.auth = (cfg["username"], cfg["password"])
        self.verify = cfg["verify"]
        self.index_pattern = cfg["index_pattern"]
        self.client = httpx.Client(
            auth=self.auth,
            verify=self.verify,
            timeout=max(30, cfg["timeout_seconds"]),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    def get(self, path: str, **kwargs: Any) -> dict | list:
        response = self.client.get(f"{self.base_url}{path}", **kwargs)
        response.raise_for_status()
        return response.json()

    def post(self, path: str, body: dict, **kwargs: Any) -> dict:
        response = self.client.post(f"{self.base_url}{path}", json=body, **kwargs)
        response.raise_for_status()
        return response.json()

    def cluster_health(self) -> dict[str, Any]:
        payload = self.get("/_cluster/health")
        assert isinstance(payload, dict)
        fields = (
            "status",
            "number_of_nodes",
            "number_of_data_nodes",
            "active_primary_shards",
            "active_shards",
            "unassigned_shards",
            "number_of_pending_tasks",
            "active_shards_percent_as_number",
        )
        return {field: payload.get(field) for field in fields}

    def heap(self) -> dict[str, Any]:
        payload = self.get("/_nodes/stats/jvm")
        assert isinstance(payload, dict)
        nodes = payload.get("nodes") or {}
        readings = []
        for node_id, node in nodes.items():
            memory = ((node.get("jvm") or {}).get("mem") or {})
            readings.append(
                {
                    "node_id": node_id,
                    "heap_used_percent": memory.get("heap_used_percent"),
                    "heap_used_bytes": memory.get("heap_used_in_bytes"),
                    "heap_max_bytes": memory.get("heap_max_in_bytes"),
                }
            )
        used = [
            float(item["heap_used_percent"])
            for item in readings
            if item.get("heap_used_percent") is not None
        ]
        return {
            "max_heap_used_percent": max(used) if used else None,
            "nodes": readings,
        }

    def indices(self) -> list[dict[str, Any]]:
        payload = self.get(
            "/_cat/indices/wazuh-alerts-*,wazuh-archives-*",
            params={
                "format": "json",
                "bytes": "b",
                "h": "health,status,index,docs.count,docs.deleted,store.size,pri.store.size",
            },
        )
        return payload if isinstance(payload, list) else []

    def count_window(self, minutes: int, query: dict | None = None) -> int:
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{minutes}m",
                                    "lte": "now",
                                }
                            }
                        }
                    ],
                    "must": [query or {"match_all": {}}],
                }
            }
        }
        payload = self.post(
            f"/{self.index_pattern}/_count",
            body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        return int(payload.get("count") or 0)


def _orchestrator_get(path: str) -> Any:
    api_key = os.environ["ORCHESTRATOR_API_KEY"]
    response = httpx.get(
        f"http://localhost:8200{path}",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def _live_hypotheses() -> list[dict[str, Any]]:
    payload = _orchestrator_get("/hypotheses")
    return payload if isinstance(payload, list) else []


def _unique_techniques(hypotheses: list[dict[str, Any]], limit: int) -> list[str]:
    techniques: list[str] = []
    for item in hypotheses:
        technique = str(item.get("technique") or "").strip().upper()
        if technique.startswith("T") and technique not in techniques:
            techniques.append(technique)
        if len(techniques) >= limit:
            break
    return techniques


def _technique_query(technique: str) -> str:
    return json.dumps(
        {"query": {"term": {"rule.mitre.id": technique}}},
        separators=(",", ":"),
    )


def _connector_profile(techniques: list[str], repeats: int) -> dict[str, Any]:
    queries = [("*", "*"), *[(item, _technique_query(item)) for item in techniques]]
    rows = []
    for label, query in queries:
        latencies: list[float] = []
        total_hits: list[int] = []
        failures: list[str] = []
        for _ in range(repeats):
            try:
                result, elapsed = _timed(lambda q=query: wazuh.fetch_logs(q, 25))
                latencies.append(elapsed)
                total_hits.append(int(result.get("total_hits") or 0))
            except Exception as exc:  # preserve the test matrix after one failure
                failures.append(str(exc))
        rows.append(
            {
                "query": label,
                "latency": _latency_summary(latencies),
                "total_hits": max(total_hits) if total_hits else None,
                "failures": failures,
            }
        )
    return {"queries": rows}


def _concurrent_connector_profile(
    queries: list[str],
    concurrency_levels: list[int],
    indexer: IndexerClient,
    heap_stop_percent: float,
) -> list[dict[str, Any]]:
    results = []
    for concurrency in concurrency_levels:
        before = indexer.heap()
        if (
            before["max_heap_used_percent"] is not None
            and before["max_heap_used_percent"] >= heap_stop_percent
        ):
            results.append(
                {
                    "concurrency": concurrency,
                    "status": "skipped_heap_safety_gate",
                    "heap_before": before,
                }
            )
            break
        started = time.perf_counter()
        latencies: list[float] = []
        errors: list[str] = []
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(_timed, lambda q=query: wazuh.fetch_logs(q, 10))
                for query in queries[: max(concurrency * 2, 2)]
            ]
            for future in as_completed(futures):
                try:
                    _result, elapsed = future.result()
                    latencies.append(elapsed)
                except Exception as exc:
                    errors.append(str(exc))
        wall_ms = (time.perf_counter() - started) * 1000
        after = indexer.heap()
        results.append(
            {
                "concurrency": concurrency,
                "status": "completed" if not errors else "completed_with_errors",
                "requests": len(latencies) + len(errors),
                "errors": errors,
                "wall_ms": round(wall_ms, 3),
                "request_latency": _latency_summary(latencies),
                "throughput_requests_per_second": round(
                    len(latencies) / max(wall_ms / 1000, 0.001), 3
                ),
                "heap_before": before,
                "heap_after": after,
            }
        )
        if (
            after["max_heap_used_percent"] is not None
            and after["max_heap_used_percent"] >= heap_stop_percent
        ):
            break
    return results


def _distributed_rule_ids(all_ids: list[str], count: int) -> list[str]:
    if count >= len(all_ids):
        return list(all_ids)
    stride = len(all_ids) / count
    selected = []
    for index in range(count):
        candidate = all_ids[min(int(index * stride), len(all_ids) - 1)]
        if candidate not in selected:
            selected.append(candidate)
    return selected


async def _rule_batch_profile(
    all_ids: list[str],
    indexer: IndexerClient,
    heap_stop_percent: float,
    batch_sizes: list[int],
) -> list[dict[str, Any]]:
    rows = []
    for batch_size in batch_sizes:
        before = indexer.heap()
        if (
            before["max_heap_used_percent"] is not None
            and before["max_heap_used_percent"] >= heap_stop_percent
        ):
            rows.append(
                {
                    "batch_size": batch_size,
                    "status": "skipped_heap_safety_gate",
                    "heap_before": before,
                }
            )
            break
        selected = _distributed_rule_ids(all_ids, batch_size)
        metadata = [find_rule(rule_id, "wazuh") for rule_id in selected]
        started = time.perf_counter()
        try:
            results = await run_scheduled_sigma_batch(
                schedule_id=(
                    "enterprise-regression-"
                    + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                    + f"-{batch_size}"
                ),
                rule_ids=selected,
                siem_type="wazuh",
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            errors = [str(item.get("error")) for item in results if item.get("error")]
            status_counts: dict[str, int] = {}
            for item in results:
                status = str(item.get("status") or "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
            row = {
                "batch_size": batch_size,
                "status": "completed" if not errors else "completed_with_errors",
                "duration_ms": round(elapsed_ms, 3),
                "rules_per_second": round(
                    len(results) / max(elapsed_ms / 1000, 0.001), 3
                ),
                "status_counts": status_counts,
                "events_matched": sum(int(item.get("events_matched") or 0) for item in results),
                "errors": errors,
                "selected_rules": [
                    {
                        "rule_id": item["rule_id"],
                        "title": item.get("title"),
                        "level": item.get("level"),
                    }
                    for item in metadata
                ],
            }
        except Exception as exc:
            row = {
                "batch_size": batch_size,
                "status": "failed",
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "errors": [str(exc)],
            }
        row["heap_before"] = before
        row["heap_after"] = indexer.heap()
        row["cluster_after"] = indexer.cluster_health()
        rows.append(row)
        after_percent = row["heap_after"].get("max_heap_used_percent")
        if row["status"] == "failed" or (
            after_percent is not None and after_percent >= heap_stop_percent
        ):
            break
    return rows


def _evidence_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return [path for path in root.rglob("*") if path.is_file()][:1000]


def _file_scan_profile(root: Path, enabled: bool) -> dict[str, Any]:
    files = _evidence_files(root)
    total_bytes = sum(path.stat().st_size for path in files)
    result: dict[str, Any] = {
        "enabled": enabled,
        "root": str(root),
        "files_discovered": len(files),
        "bytes_discovered": total_bytes,
        "catalog": catalog_summary(),
    }
    if not enabled:
        return result
    scan, elapsed_ms = _timed(lambda: scan_paths(files))
    result.update(
        {
            "duration_ms": round(elapsed_ms, 3),
            "files_scanned": scan.get("files_scanned"),
            "matched_files": scan.get("matched_files"),
            "match_count": scan.get("match_count"),
            "error_count": len(scan.get("errors") or []),
            "errors": scan.get("errors") or [],
            "throughput_files_per_second": round(
                int(scan.get("files_scanned") or 0)
                / max(elapsed_ms / 1000, 0.001),
                3,
            ),
            "throughput_mib_per_second": round(
                (total_bytes / 1024 / 1024) / max(elapsed_ms / 1000, 0.001),
                3,
            ),
        }
    )
    return result


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--techniques", type=int, default=8)
    parser.add_argument("--heap-stop-percent", type=float, default=70)
    parser.add_argument("--scan-files", action="store_true")
    parser.add_argument("--evidence-root", default="/data/log_sources")
    args = parser.parse_args()

    started_at = datetime.now(timezone.utc)
    indexer = IndexerClient()
    hypotheses = _live_hypotheses()
    techniques = _unique_techniques(hypotheses, max(1, args.techniques))
    rule_ids = ready_rule_ids("wazuh")
    indices = indexer.indices()
    documents = sum(int(item.get("docs.count") or 0) for item in indices)
    storage_bytes = sum(int(item.get("store.size") or 0) for item in indices)

    connector_profile = _connector_profile(techniques, max(1, args.repeats))
    live_queries = [
        _technique_query(item)
        for item in techniques
    ] or ["*"]

    report = {
        "test_kind": "live_enterprise_regression",
        "synthetic_events_used": False,
        "started_at": started_at.isoformat(),
        "configuration": {
            "connector": "wazuh",
            "lookback_minutes": wazuh._get_config()["lookback_minutes"],
            "connector_max_results": wazuh._get_config()["max_results"],
            "heap_stop_percent": args.heap_stop_percent,
        },
        "inventory": {
            "hypotheses": len(hypotheses),
            "unique_techniques_sampled": techniques,
            "ready_detection_rules": len(rule_ids),
            "indices": len(indices),
            "documents_across_alert_and_archive_indices": documents,
            "storage_bytes": storage_bytes,
            "events_last_24h": indexer.count_window(24 * 60),
            "events_last_7d": indexer.count_window(7 * 24 * 60),
            "cluster": indexer.cluster_health(),
            "jvm": indexer.heap(),
        },
        "connector_searches": connector_profile,
        "concurrent_searches": _concurrent_connector_profile(
            live_queries,
            [1, 2, 4],
            indexer,
            args.heap_stop_percent,
        ),
        "detection_rule_batches": await _rule_batch_profile(
            rule_ids,
            indexer,
            args.heap_stop_percent,
            [1, 2, 4],
        ),
        "file_scanning": _file_scan_profile(
            Path(args.evidence_root),
            args.scan_files,
        ),
        "final_cluster": indexer.cluster_health(),
        "final_jvm": indexer.heap(),
    }
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report["duration_ms"] = round(
        (datetime.now(timezone.utc) - started_at).total_seconds() * 1000,
        3,
    )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
