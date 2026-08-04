"""Deterministic anomaly and entity lead generation for THOS."""

from services.anomaly.engine import build_observations, evaluate_anomalies

__all__ = ["build_observations", "evaluate_anomalies"]
