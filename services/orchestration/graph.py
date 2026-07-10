"""
LangGraph state machine implementing:

  refresh_hearth_kb -> hypothesis -> query_gen -> siem_fetch -> log_processing
    -> soc_tools -> reasoning -> [need_more_logs? -> siem_fetch (loop) : report -> END]

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


def route_after_reasoning(state: HuntState) -> str:
    return "siem_fetch" if state.get("need_more_logs") else "report"


def build_graph():
    graph = StateGraph(HuntState)

    graph.add_node("refresh_hearth_kb", refresh_hearth_kb_node)
    graph.add_node("hypothesis", select_hypothesis)
    graph.add_node("query_gen", generate_query_node)
    graph.add_node("siem_fetch", fetch_logs_node)
    graph.add_node("log_processing", process_logs_node)
    graph.add_node("soc_tools", run_soc_tools_node)
    graph.add_node("reasoning", reason_node)
    graph.add_node("report", write_report_node)

    graph.set_entry_point("refresh_hearth_kb")
    graph.add_edge("refresh_hearth_kb", "hypothesis")
    graph.add_edge("hypothesis", "query_gen")
    graph.add_edge("query_gen", "siem_fetch")
    graph.add_edge("siem_fetch", "log_processing")
    graph.add_edge("log_processing", "soc_tools")
    graph.add_edge("soc_tools", "reasoning")
    graph.add_conditional_edges("reasoning", route_after_reasoning, {
        "siem_fetch": "siem_fetch",
        "report": "report",
    })
    graph.add_edge("report", END)

    return graph.compile()


compiled_graph = build_graph()
