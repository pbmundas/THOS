"""
LangGraph state machine implementing:

  refresh_hearth_kb -> hypothesis -> supervisor -> query_gen -> siem_fetch
    -> log_processing -> guardrail -> soc_tools -> coverage/enrichment
    -> adaptive retrieval -> evidence gate -> reasoning
    -> [need_more_logs? -> siem_fetch (loop) : verifier -> report -> END]

refresh_hearth_kb pulls the latest hypotheses from the live HEARTH GitHub
repo (rate-limited via Redis so it doesn't re-fetch on every hunt — see
services/hunting/kb_refresh.py) before hypothesis selection runs.

Extension point (Phase 4): add more conditional branches — e.g. a
analyst-review case creation before `report`, parallel fan-out to multiple SOC
tools, or a dedicated "escalate" node that pages a human analyst when
confidence is low.
"""
import json

from langgraph.graph import StateGraph, END

from services.orchestration.state import HuntState
from services.hunting.kb_refresh import refresh_hearth_kb_node
from services.hunting.hypothesis import select_hypothesis
from services.hunting.query_gen import generate_query_node
from services.siem.siem_fetch import fetch_logs_node
from services.siem.log_processing import process_logs_node
from services.mcp.soc_tools import run_soc_tools_node
from services.reasoning.reasoning import negative_screening_gate_node, reason_node
from services.reporting.report import write_report_node
from services.orchestration.supervisor import adaptive_replan_node, plan_hunt_node
from services.guardrails.sentinel import guardrail_node
from services.verification.verifier import verify_findings_node
from services.coverage.gap_analysis import coverage_gap_node
from services.enrichment.threat_intel import enrich_iocs_node
from services.detection_engineering.rule_drafter import draft_detection_rule_node
from services.memory.hunt_memory import recall_hunt_memory_node
from services.communication.audience import communicate_node


def route_after_reasoning(state: HuntState) -> str:
    if state.get("reasoning_failed"):
        return "failed"
    if state.get("reasoning_skipped"):
        return "no_evidence"
    follow_up = (state.get("follow_up_query") or "").strip()
    source = str(
        state.get("follow_up_source")
        or state.get("active_query_source")
        or state.get("siem_type")
        or "folder"
    )
    lookback = int(
        state.get("follow_up_lookback_minutes")
        or state.get("active_lookback_minutes")
        or 1440
    )
    limit = int(
        state.get("follow_up_limit")
        or state.get("active_query_limit")
        or state.get("log_limit")
        or 25
    )
    attempt_key = json.dumps({
        "source": source,
        "query": follow_up,
        "lookback_minutes": lookback,
        "limit": limit,
    }, sort_keys=True, separators=(",", ":"))
    # One targeted refinement is useful; repeated full-pipeline loops are
    # expensive and tend to re-analyze the same data rather than add evidence.
    can_follow_up = (
        state.get("need_more_logs")
        and follow_up
        and state.get("iteration", 0) <= state.get("max_reasoning_followups", 1)
        and attempt_key not in (state.get("executed_query_keys") or [])
    )
    return "siem_fetch" if can_follow_up else "verifier"


def route_after_adaptive_replan(state: HuntState) -> str:
    return (
        "siem_fetch"
        if state.get("replan_action") == "refine_query"
        else "negative_screening_gate"
    )


def route_after_negative_screening(state: HuntState) -> str:
    return "no_evidence" if state.get("reasoning_skipped") else "reasoning"


def route_after_verifier(state: HuntState) -> str:
    return "failed" if state.get("verification_failed") else "continue"


def build_graph():
    graph = StateGraph(HuntState)

    graph.add_node("refresh_hearth_kb", refresh_hearth_kb_node)
    graph.add_node("hypothesis", select_hypothesis)
    graph.add_node("hunt_memory", recall_hunt_memory_node)
    graph.add_node("supervisor", plan_hunt_node)
    graph.add_node("query_gen", generate_query_node)
    graph.add_node("siem_fetch", fetch_logs_node)
    graph.add_node("log_processing", process_logs_node)
    graph.add_node("guardrail", guardrail_node)
    graph.add_node("soc_tools", run_soc_tools_node)
    graph.add_node("coverage_gap", coverage_gap_node)
    graph.add_node("adaptive_replan", adaptive_replan_node)
    graph.add_node("threat_intel", enrich_iocs_node)
    graph.add_node("negative_screening_gate", negative_screening_gate_node)
    graph.add_node("reasoning", reason_node)
    graph.add_node("verifier", verify_findings_node)
    graph.add_node("detection_engineering", draft_detection_rule_node)
    graph.add_node("communication", communicate_node)
    graph.add_node("report", write_report_node)

    graph.set_entry_point("refresh_hearth_kb")
    graph.add_edge("refresh_hearth_kb", "hypothesis")
    graph.add_edge("hypothesis", "hunt_memory")
    graph.add_edge("hunt_memory", "supervisor")
    graph.add_edge("supervisor", "query_gen")
    graph.add_edge("query_gen", "siem_fetch")
    graph.add_edge("siem_fetch", "log_processing")
    graph.add_edge("log_processing", "guardrail")
    graph.add_edge("guardrail", "soc_tools")
    graph.add_edge("soc_tools", "coverage_gap")
    graph.add_edge("coverage_gap", "threat_intel")
    # Retrieval is allowed to broaden, tighten, expand its bounded time
    # window, or query another selected source before the no-evidence gate
    # terminates the hunt. This prevents a narrow zero-result primary query
    # from being mistaken for a completed investigation.
    graph.add_edge("threat_intel", "adaptive_replan")
    graph.add_conditional_edges("adaptive_replan", route_after_adaptive_replan, {
        "siem_fetch": "siem_fetch",
        "negative_screening_gate": "negative_screening_gate",
    })
    graph.add_conditional_edges(
        "negative_screening_gate",
        route_after_negative_screening,
        {"reasoning": "reasoning", "no_evidence": END},
    )
    graph.add_conditional_edges("reasoning", route_after_reasoning, {
        "siem_fetch": "siem_fetch",
        "verifier": "verifier",
        "failed": END,
        "no_evidence": END,
    })
    graph.add_conditional_edges(
        "verifier",
        route_after_verifier,
        {"continue": "detection_engineering", "failed": END},
    )
    graph.add_edge("detection_engineering", "communication")
    graph.add_edge("communication", "report")
    graph.add_edge("report", END)

    return graph.compile()


compiled_graph = build_graph()
