"""Continuous anomaly monitoring service built on the normal SIEM fetch path."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.anomaly.engine import build_observations, evaluate_anomalies
from services.mcp.mcp_client import call_tool
from services.observability import audit
from services.runtime_config import get_value
from services.siem.log_processing import process_logs_node


READ_ONLY_BASELINE_QUERIES: dict[str, Any] = {
    "wazuh": '{"query":{"match_all":{}}}',
    "elasticsearch": '{"query":{"match_all":{}}}',
    "splunk": "search *",
    "qradar": "SELECT * FROM events",
    "logrhythm": "*",
    "folder": "",
    "mock": "*",
}


def _bucket_start(now: datetime, interval_minutes: int) -> datetime:
    utc_now = now.astimezone(timezone.utc)
    minute = (utc_now.minute // interval_minutes) * interval_minutes
    return utc_now.replace(minute=minute, second=0, microsecond=0)


async def evaluate_source(
    source: str,
    *,
    lookback_minutes: int | None = None,
    limit: int | None = None,
    log_source_path: str = "",
) -> dict:
    """Fetch one bounded window, update baselines, and persist recurring leads."""
    source = source.strip().lower()
    if source not in READ_ONLY_BASELINE_QUERIES:
        raise ValueError(f"Continuous anomaly monitoring is not supported for source '{source}'")

    interval = max(5, min(1440, int(get_value(
        "anomaly_monitoring", "interval_minutes", default=15,
    ))))
    lookback = max(1, min(1440, int(lookback_minutes or get_value(
        "anomaly_monitoring", "lookback_minutes", default=interval,
    ))))
    fetch_limit = max(1, min(5000, int(limit or get_value(
        "anomaly_monitoring", "limit", default=2000,
    ))))
    history_days = max(1, min(365, int(get_value(
        "anomaly_monitoring", "history_days", default=30,
    ))))
    minimum_buckets = max(3, min(10_000, int(get_value(
        "anomaly_monitoring", "minimum_baseline_buckets", default=24,
    ))))
    now = datetime.now(timezone.utc)
    bucket = _bucket_start(now, interval)
    run = await audit.start_anomaly_run(source, lookback)
    run_id = str(run["run_id"])
    record_count = observation_count = lead_count = 0
    try:
        result = await call_tool("fetch_siem_logs", {
            "query": READ_ONLY_BASELINE_QUERIES[source],
            "limit": fetch_limit,
            "siem_type": source,
            "log_source_path": log_source_path,
            "bypass_cache": True,
            "lookback_minutes": lookback,
        })
        if not isinstance(result, dict):
            raise RuntimeError("Telemetry source returned an invalid response")
        if result.get("error"):
            raise RuntimeError(str(result["error"]))
        records = [row for row in result.get("logs") or [] if isinstance(row, dict)]
        total_hits = max(len(records), int(result.get("total_hits") or len(records)))
        sampling_limited = total_hits > len(records)
        normalized = await process_logs_node({
            "logs": records,
            "active_query_source": source,
            "siem_type": source,
        })
        processed = list(normalized.get("processed_logs") or [])
        record_count = len(processed)
        # A newest-N sample is not a measured activity baseline. At enterprise
        # EPS it can hide entities outside the row cap and create false rarity.
        # Pause statistical scoring until the SIEM query is scoped tightly
        # enough to fit or a source-native aggregation path is configured.
        observations = [] if sampling_limited else build_observations(processed, source, bucket)
        observation_count = len(observations)
        history = await audit.list_anomaly_observations(
            source,
            bucket - timedelta(days=history_days),
            before=bucket,
        )
        leads = evaluate_anomalies(
            observations,
            history,
            min_baseline_buckets=minimum_buckets,
            spike_threshold=float(get_value(
                "anomaly_monitoring", "spike_threshold", default=4.0,
            )),
            minimum_observed=max(1, int(get_value(
                "anomaly_monitoring", "minimum_observed", default=5,
            ))),
            relationship_minimum_observed=max(1, int(get_value(
                "anomaly_monitoring", "relationship_minimum_observed", default=2,
            ))),
        )
        lead_count = len(leads)
        await audit.upsert_anomaly_observations(observations)
        await audit.upsert_anomaly_leads(leads)
        auto_close_hours = max(1, int(get_value(
            "anomaly_monitoring", "auto_close_hours", default=24,
        )))
        closed_count = await audit.close_stale_anomaly_leads(
            source, now - timedelta(hours=auto_close_hours),
        )
        await audit.complete_anomaly_run(
            run_id,
            "completed",
            records_analyzed=record_count,
            observation_count=observation_count,
            lead_count=lead_count,
        )
        prior_buckets = len({str(row.get("bucket_start") or "") for row in history})
        return {
            "run_id": run_id,
            "source": source,
            "status": "completed",
            "records_analyzed": record_count,
            "total_hits": total_hits,
            "sampling_limited": sampling_limited,
            "sampling_message": (
                "The SIEM window exceeded its row safety budget. Statistical baseline updates were paused; use a narrower anomaly source/index or source-native aggregation."
                if sampling_limited else ""
            ),
            "retrieval_policy": result.get("retrieval_policy") or {},
            "observation_count": observation_count,
            "lead_count": lead_count,
            "closed_count": closed_count,
            "bucket_start": bucket,
            "baseline_bucket_count": prior_buckets,
            "minimum_baseline_buckets": minimum_buckets,
            "warming": prior_buckets < minimum_buckets,
            "leads": leads,
        }
    except Exception as exc:
        await audit.complete_anomaly_run(
            run_id,
            "failed",
            records_analyzed=record_count,
            observation_count=observation_count,
            lead_count=lead_count,
            error_msg=str(exc),
        )
        raise
