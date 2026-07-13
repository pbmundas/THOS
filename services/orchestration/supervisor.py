"""Deterministic first-pass supervisor for adaptive hunt execution.

The supervisor deliberately does not make autonomous write decisions.  It
selects read-only analysis branches from observable hunt context; later model
assisted planning can be enabled through the model router without changing the
graph contract.
"""
from services.orchestration.state import HuntState


async def plan_hunt_node(state: HuntState) -> dict:
    hypothesis = (state.get("hypothesis_text") or "").lower()
    plan = ["guardrail", "query_gen", "siem_fetch", "log_processing", "soc_tools", "reasoning", "verifier", "report"]
    ioc_markers = ("ip", "domain", "hash", "indicator", "ioc", "c2", "dns")
    if any(marker in hypothesis for marker in ioc_markers):
        plan.insert(5, "threat_intel_enrichment")
    if state.get("siem_type") in {"folder", "local_folder", "file", "local"}:
        plan.insert(-1, "coverage_gap_check")
    return {"plan": plan}
