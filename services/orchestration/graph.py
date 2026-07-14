"""
LangGraph state machine implementing:

  refresh_hearth_kb -> hypothesis -> supervisor -> query_gen -> siem_fetch
    -> log_processing -> guardrail -> soc_tools -> reasoning
    -> [need_more_logs? -> siem_fetch (loop) : verifier -> report -> END]

refresh_hearth_kb pulls the latest hypotheses from the live HEARTH GitHub
repo (rate-limited via Redis so it doesn't re-fetch on every hunt — see
services/hunting/kb_refresh.py) before hypothesis selection runs.

Extension point (Phase 4): add more conditional branches — e.g. a
human-approval gate before `report`, parallel fan-out to multiple SOC
tools, or a dedicated "escalate" node that pages a human analyst when
confidence is low.
"""
from langgraph.graph import StateGraph, END

from services.orchestration.state import HuntState
from services.hunting.kb_refresh import refresh_hearth_kb_node
from services.hunting.hypothesis import select_hypothesis
from services.hunting.query_gen import generate_query_node
from services.siem.siem_fetch import fetch_logs_node
from services.siem.log_processing import process_logs_node
from services.mcp.soc_tools import run_soc_tools_node
from services.reasoning.reasoning import reason_node
from services.reporting.report import write_report_node
from services.orchestration.supervisor import plan_hunt_node
from services.guardrails.sentinel import guardrail_node
from services.verification.verifier import verify_findings_node
from services.coverage.gap_analysis import coverage_gap_node
from services.enrichment.threat_intel import enrich_iocs_node
from services.detection_engineering.rule_drafter import draft_detection_rule_node
from services.memory.hunt_memory import recall_hunt_memory_node
from services.communication.audience import communicate_node


def route_after_reasoning(state: HuntState) -> str:
    follow_up = (state.get("follow_up_query") or "").strip()
    # One targeted refinement is useful; repeated full-pipeline loops are
    # expensive and tend to re-analyze the same data rather than add evidence.
    can_follow_up = (
        state.get("need_more_logs")
        and follow_up
        and state.get("iteration", 0) <= state.get("max_reasoning_followups", 1)
        and follow_up not in (state.get("executed_queries") or [])
    )
    return "siem_fetch" if can_follow_up else "verifier"


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
    graph.add_node("threat_intel", enrich_iocs_node)
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
    graph.add_edge("threat_intel", "reasoning")
    graph.add_conditional_edges("reasoning", route_after_reasoning, {
        "siem_fetch": "siem_fetch",
        "verifier": "verifier",
    })
    graph.add_edge("verifier", "detection_engineering")
    graph.add_edge("detection_engineering", "communication")
    graph.add_edge("communication", "report")
    graph.add_edge("report", END)

    return graph.compile()


compiled_graph = build_graph()
